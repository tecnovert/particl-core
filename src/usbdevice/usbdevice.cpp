// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <usbdevice/usbdevice.h>

#include <usbdevice/debugdevice.h>
#include <usbdevice/ledgerdevice.h>
#include <usbdevice/trezordevice.h>

#include <hidapi/hidapi.h>
#include <stdio.h>
#include <inttypes.h>
#include <univalue.h>
#include <chainparams.h>

#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#endif

#include <google/protobuf/stubs/common.h>

#include <libusb-1.0/libusb.h>
#include <wchar.h>
#include <iconv.h>

/* Linked List of input reports received from the device. */
struct input_report {
    uint8_t *data;
    size_t len;
    struct input_report *next;
};

struct hid_device_ {
    /* Handle to the actual device. */
    libusb_device_handle *device_handle;

    /* Endpoint information */
    int input_endpoint;
    int output_endpoint;
    int input_ep_max_packet_size;

    /* The interface number of the HID */
    int interface;

    /* Indexes of Strings */
    int manufacturer_index;
    int product_index;
    int serial_index;

    /* Whether blocking reads are used */
    int blocking; /* boolean */

    /* Read thread objects */
    pthread_t thread;
    pthread_mutex_t mutex; /* Protects input_reports */
    pthread_cond_t condition;
    pthread_barrier_t barrier; /* Ensures correct startup sequence */
    int shutdown_thread;
    int cancelled;
    struct libusb_transfer *transfer;

    /* List of received input reports. */
    struct input_report *input_reports;
};

namespace usb_device {

const DeviceType usbDeviceTypes[] = {
    DeviceType(0xffff, 0x0001, "Debug", "Device", USBDEVICE_DEBUG),
    DeviceType(0x2c97, 0x0001, "Ledger", "Nano S", USBDEVICE_LEDGER_NANO_S),
    //DeviceType(0x534c, 0x0001, "Trezor", "One", USBDEVICE_TREZOR_ONE),
    DeviceType(0x1209, 0x53c1, "Trezor", "One", USBDEVICE_TREZOR_ONE), // webusb
};

void ShutdownHardwareIntegration()
{
    // Safe to call ShutdownProtobufLibrary multiple times
    google::protobuf::ShutdownProtobufLibrary();
}

int CUSBDevice::GetFirmwareVersion(std::string &sFirmware, std::string &sError)
{
    sFirmware = "no_device";
    return 0;
};

int CUSBDevice::GetInfo(UniValue &info, std::string &sError)
{
    info.pushKV("error", "no_device");
    return 0;
};

static bool MatchLedgerInterface(struct hid_device_info *cur_dev)
{
#ifdef MAC_OSX
    return cur_dev->usage_page == 0xffa0;
#endif
#ifdef WIN32
    return cur_dev->usage_page == 0xffa0;
#endif
    return cur_dev->interface_number == 0;
}

static bool MatchTrezorInterface(struct hid_device_info *cur_dev)
{
#ifdef MAC_OSX
    return cur_dev->usage_page == 0xff00;
#endif
#ifdef WIN32
    return cur_dev->usage_page == 0xff00;
#endif
    return cur_dev->interface_number == 0;
}


static libusb_context *usb_context = NULL;
/* Get the first language the device says it reports. This comes from
   USB string #0. */
static uint16_t get_first_language(libusb_device_handle *dev)
{
    uint16_t buf[32];
    int len;

    /* Get the string from libusb. */
    len = libusb_get_string_descriptor(dev,
            0x0, /* String ID */
            0x0, /* Language */
            (unsigned char*)buf,
            sizeof(buf));
    if (len < 4)
        return 0x0;

    return buf[1]; /* First two bytes are len and descriptor type. */
}
/* This function returns a newly allocated wide string containing the USB
   device string numbered by the index. The returned string must be freed
   by using free(). */
static wchar_t *get_usb_string(libusb_device_handle *dev, uint8_t idx)
{
    char buf[512];
    int len;
    wchar_t *str = NULL;

#ifndef __ANDROID__ /* we don't use iconv on Android */
    wchar_t wbuf[256];
    /* iconv variables */
    iconv_t ic;
    size_t inbytes;
    size_t outbytes;
    size_t res;
#ifdef __FreeBSD__
    const char *inptr;
#else
    char *inptr;
#endif
    char *outptr;
#endif

    /* Determine which language to use. */
    uint16_t lang;
    //lang = get_usb_code_for_current_locale();
    //if (!is_language_supported(dev, lang))
        lang = get_first_language(dev);

    /* Get the string from libusb. */
    len = libusb_get_string_descriptor(dev,
            idx,
            lang,
            (unsigned char*)buf,
            sizeof(buf));
    if (len < 0)
        return NULL;

#ifdef __ANDROID__

    /* Bionic does not have iconv support nor wcsdup() function, so it
       has to be done manually.  The following code will only work for
       code points that can be represented as a single UTF-16 character,
       and will incorrectly convert any code points which require more
       than one UTF-16 character.

       Skip over the first character (2-bytes).  */
    len -= 2;
    str = malloc((len / 2 + 1) * sizeof(wchar_t));
    int i;
    for (i = 0; i < len / 2; i++) {
        str[i] = buf[i * 2 + 2] | (buf[i * 2 + 3] << 8);
    }
    str[len / 2] = 0x00000000;

#else

    /* buf does not need to be explicitly NULL-terminated because
       it is only passed into iconv() which does not need it. */

    /* Initialize iconv. */
    ic = iconv_open("WCHAR_T", "UTF-16LE");
    if (ic == (iconv_t)-1) {
        //LOG("iconv_open() failed\n");
        return NULL;
    }

    /* Convert to native wchar_t (UTF-32 on glibc/BSD systems).
       Skip the first character (2-bytes). */
    inptr = buf+2;
    inbytes = len-2;
    outptr = (char*) wbuf;
    outbytes = sizeof(wbuf);
    res = iconv(ic, &inptr, &inbytes, &outptr, &outbytes);
    if (res == (size_t)-1) {
        //LOG("iconv() failed\n");
        goto err;
    }

    /* Write the terminating NULL. */
    wbuf[sizeof(wbuf)/sizeof(wbuf[0])-1] = 0x00000000;
    if (outbytes >= sizeof(wbuf[0]))
        *((wchar_t*)outptr) = 0x00000000;

    /* Allocate and copy the string. */
    str = wcsdup(wbuf);

err:
    iconv_close(ic);

#endif

    return str;
}

static char *make_path(libusb_device *dev, int interface_number)
{
    char str[64];
    snprintf(str, sizeof(str), "%04x:%04x:%02x",
        libusb_get_bus_number(dev),
        libusb_get_device_address(dev),
        interface_number);
    str[sizeof(str)-1] = '\0';

    return strdup(str);
}
struct hid_device_info *libusb_enumerate()
{
    libusb_device **devs;
    libusb_device *dev;
    libusb_device_handle *handle;
    ssize_t num_devs;
    int i = 0;

    struct hid_device_info *root = NULL; /* return object */
    struct hid_device_info *cur_dev = NULL;

    num_devs = libusb_get_device_list(usb_context, &devs);
    if (num_devs < 0)
        return NULL;
    while ((dev = devs[i++]) != NULL) {
        struct libusb_device_descriptor desc;
        struct libusb_config_descriptor *conf_desc = NULL;
        int j, k;
        int interface_num = 0;

        int res = libusb_get_device_descriptor(dev, &desc);
        unsigned short dev_vid = desc.idVendor;
        unsigned short dev_pid = desc.idProduct;

        res = libusb_get_active_config_descriptor(dev, &conf_desc);
        if (res < 0)
            libusb_get_config_descriptor(dev, 0, &conf_desc);
        if (conf_desc) {
            for (j = 0; j < conf_desc->bNumInterfaces; j++) {
                const struct libusb_interface *intf = &conf_desc->interface[j];
                for (k = 0; k < intf->num_altsetting; k++) {
                    const struct libusb_interface_descriptor *intf_desc;
                    intf_desc = &intf->altsetting[k];
                    if (intf_desc->bInterfaceClass == LIBUSB_CLASS_HID
                        || (intf_desc->bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC && dev_vid == 0x1209 && dev_pid == 0x53c1)) {
                    //if (intf_desc->bInterfaceClass == LIBUSB_CLASS_HID) {
                        interface_num = intf_desc->bInterfaceNumber;

                        struct hid_device_info *tmp;

                        tmp = (struct hid_device_info*) calloc(1, sizeof(struct hid_device_info));
                        if (cur_dev) {
                            cur_dev->next = tmp;
                        }
                        else {
                            root = tmp;
                        }
                        cur_dev = tmp;

                        /* Fill out the record */
                        cur_dev->next = NULL;
                        cur_dev->path = make_path(dev, interface_num);

                        res = libusb_open(dev, &handle);

                        if (res >= 0) {
                            /* Serial Number */
                            if (desc.iSerialNumber > 0)
                                cur_dev->serial_number =
                                    get_usb_string(handle, desc.iSerialNumber);

                            /* Manufacturer and Product strings */
                            if (desc.iManufacturer > 0)
                                cur_dev->manufacturer_string =
                                    get_usb_string(handle, desc.iManufacturer);
                            if (desc.iProduct > 0)
                                cur_dev->product_string =
                                    get_usb_string(handle, desc.iProduct);
                            libusb_close(handle);
                        }
                        /* VID/PID */
                        cur_dev->vendor_id = dev_vid;
                        cur_dev->product_id = dev_pid;

                        /* Release Number */
                        cur_dev->release_number = desc.bcdDevice;

                        /* Interface Number */
                        cur_dev->interface_number = interface_num;
                    }
                } /* altsettings */
            } /* interfaces */
            libusb_free_config_descriptor(conf_desc);
        }
    }

    libusb_free_device_list(devs, 1);

    return root;
}

static hid_device *new_hid_device(void)
{
    hid_device *dev = (hid_device*) calloc(1, sizeof(hid_device));
    dev->blocking = 1;

    pthread_mutex_init(&dev->mutex, NULL);
    pthread_cond_init(&dev->condition, NULL);
    pthread_barrier_init(&dev->barrier, NULL, 2);

    return dev;
}

static void free_hid_device(hid_device *dev)
{
    /* Clean up the thread objects */
    pthread_barrier_destroy(&dev->barrier);
    pthread_cond_destroy(&dev->condition);
    pthread_mutex_destroy(&dev->mutex);

    /* Free the device itself */
    free(dev);
}

/* Helper function, to simplify hid_read().
   This should be called with dev->mutex locked. */
static int return_data(hid_device *dev, unsigned char *data, size_t length)
{
    /* Copy the data out of the linked list item (rpt) into the
       return buffer (data), and delete the liked list item. */
    struct input_report *rpt = dev->input_reports;
    size_t len = (length < rpt->len)? length: rpt->len;
    if (len > 0)
        memcpy(data, rpt->data, len);
    dev->input_reports = rpt->next;
    free(rpt->data);
    free(rpt);
    return len;
}

static void read_callback(struct libusb_transfer *transfer)
{
    hid_device *dev = (hid_device*) transfer->user_data;
    int res;

    if (transfer->status == LIBUSB_TRANSFER_COMPLETED) {

        struct input_report *rpt = (input_report*) malloc(sizeof(*rpt));
        rpt->data = (uint8_t*)malloc(transfer->actual_length);
        memcpy(rpt->data, transfer->buffer, transfer->actual_length);
        rpt->len = transfer->actual_length;
        rpt->next = NULL;

        pthread_mutex_lock(&dev->mutex);

        /* Attach the new report object to the end of the list. */
        if (dev->input_reports == NULL) {
            /* The list is empty. Put it at the root. */
            dev->input_reports = rpt;
            pthread_cond_signal(&dev->condition);
        }
        else {
            /* Find the end of the list and attach. */
            struct input_report *cur = dev->input_reports;
            int num_queued = 0;
            while (cur->next != NULL) {
                cur = cur->next;
                num_queued++;
            }
            cur->next = rpt;

            /* Pop one off if we've reached 30 in the queue. This
               way we don't grow forever if the user never reads
               anything from the device. */
            if (num_queued > 30) {
                return_data(dev, NULL, 0);
            }
        }
        pthread_mutex_unlock(&dev->mutex);
    }
    else if (transfer->status == LIBUSB_TRANSFER_CANCELLED) {
        dev->shutdown_thread = 1;
        dev->cancelled = 1;
        return;
    }
    else if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
        dev->shutdown_thread = 1;
        dev->cancelled = 1;
        return;
    }
    else if (transfer->status == LIBUSB_TRANSFER_TIMED_OUT) {
        //LOG("Timeout (normal)\n");
    }
    else {
        //LOG("Unknown transfer code: %d\n", transfer->status);
    }

    /* Re-submit the transfer object. */
    res = libusb_submit_transfer(transfer);
    if (res != 0) {
        //LOG("Unable to submit URB. libusb error code: %d\n", res);
        dev->shutdown_thread = 1;
        dev->cancelled = 1;
    }
}


static void *read_thread(void *param)
{
    hid_device *dev = (hid_device*) param;
    unsigned char *buf;
    const size_t length = dev->input_ep_max_packet_size;

    /* Set up the transfer object. */
    buf = (unsigned char*) malloc(length);
    dev->transfer = libusb_alloc_transfer(0);
    libusb_fill_interrupt_transfer(dev->transfer,
        dev->device_handle,
        dev->input_endpoint,
        buf,
        length,
        read_callback,
        dev,
        5000/*timeout*/);

    /* Make the first submission. Further submissions are made
       from inside read_callback() */
    libusb_submit_transfer(dev->transfer);

    /* Notify the main thread that the read thread is up and running. */
    pthread_barrier_wait(&dev->barrier);

    /* Handle all the events. */
    while (!dev->shutdown_thread) {
        int res;
        res = libusb_handle_events(usb_context);
        if (res < 0) {
            /* There was an error. */
            //LOG("read_thread(): libusb reports error # %d\n", res);

            /* Break out of this loop only on fatal error.*/
            if (res != LIBUSB_ERROR_BUSY &&
                res != LIBUSB_ERROR_TIMEOUT &&
                res != LIBUSB_ERROR_OVERFLOW &&
                res != LIBUSB_ERROR_INTERRUPTED) {
                break;
            }
        }
    }

    /* Cancel any transfer that may be pending. This call will fail
       if no transfers are pending, but that's OK. */
    libusb_cancel_transfer(dev->transfer);

    while (!dev->cancelled)
        libusb_handle_events_completed(usb_context, &dev->cancelled);

    /* Now that the read thread is stopping, Wake any threads which are
       waiting on data (in hid_read_timeout()). Do this under a mutex to
       make sure that a thread which is about to go to sleep waiting on
       the condition actually will go to sleep before the condition is
       signaled. */
    pthread_mutex_lock(&dev->mutex);
    pthread_cond_broadcast(&dev->condition);
    pthread_mutex_unlock(&dev->mutex);

    /* The dev->transfer->buffer and dev->transfer objects are cleaned up
       in hid_close(). They are not cleaned up here because this thread
       could end either due to a disconnect or due to a user
       call to hid_close(). In both cases the objects can be safely
       cleaned up after the call to pthread_join() (in hid_close()), but
       since hid_close() calls libusb_cancel_transfer(), on these objects,
       they can not be cleaned up here. */

    return NULL;
}

hid_device *libusb_open_path(const char *path)
{
    hid_device *dev = NULL;

    libusb_device **devs;
    libusb_device *usb_dev;
    int res;
    int d = 0;
    int good_open = 0;

    if(hid_init() < 0)
        return NULL;

    dev = new_hid_device();

    libusb_get_device_list(usb_context, &devs);
    while ((usb_dev = devs[d++]) != NULL) {
        struct libusb_device_descriptor desc;
        struct libusb_config_descriptor *conf_desc = NULL;
        int i,j,k;
        libusb_get_device_descriptor(usb_dev, &desc);

        if (libusb_get_active_config_descriptor(usb_dev, &conf_desc) < 0)
            continue;
        for (j = 0; j < conf_desc->bNumInterfaces; j++) {
            const struct libusb_interface *intf = &conf_desc->interface[j];
            for (k = 0; k < intf->num_altsetting; k++) {
                const struct libusb_interface_descriptor *intf_desc;
                intf_desc = &intf->altsetting[k];
                if (intf_desc->bInterfaceClass == LIBUSB_CLASS_HID
                        || (intf_desc->bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC && desc.idVendor == 0x1209 && desc.idProduct == 0x53c1)) {
                    char *dev_path = make_path(usb_dev, intf_desc->bInterfaceNumber);
                    if (!strcmp(dev_path, path)) {
                        /* Matched Paths. Open this device */

                        /* OPEN HERE */
                        res = libusb_open(usb_dev, &dev->device_handle);
                        if (res < 0) {
                            //LOG("can't open device\n");
                            free(dev_path);
                            break;
                        }
                        good_open = 1;
                        res = libusb_claim_interface(dev->device_handle, intf_desc->bInterfaceNumber);
                        if (res < 0) {
                            //LOG("can't claim interface %d: %d\n", intf_desc->bInterfaceNumber, res);
                            free(dev_path);
                            libusb_close(dev->device_handle);
                            good_open = 0;
                            break;
                        }

                        /* Store off the string descriptor indexes */
                        dev->manufacturer_index = desc.iManufacturer;
                        dev->product_index      = desc.iProduct;
                        dev->serial_index       = desc.iSerialNumber;

                        /* Store off the interface number */
                        dev->interface = intf_desc->bInterfaceNumber;

                        /* Find the INPUT and OUTPUT endpoints. An
                           OUTPUT endpoint is not required. */
                        for (i = 0; i < intf_desc->bNumEndpoints; i++) {
                            const struct libusb_endpoint_descriptor *ep
                                = &intf_desc->endpoint[i];

                            /* Determine the type and direction of this
                               endpoint. */
                            int is_interrupt =
                                (ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
                                  == LIBUSB_TRANSFER_TYPE_INTERRUPT;
                            int is_output =
                                (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                                  == LIBUSB_ENDPOINT_OUT;
                            int is_input =
                                (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                                  == LIBUSB_ENDPOINT_IN;

                            /* Decide whether to use it for input or output. */
                            if (dev->input_endpoint == 0 &&
                                is_interrupt && is_input) {
                                /* Use this endpoint for INPUT */
                                dev->input_endpoint = ep->bEndpointAddress;
                                dev->input_ep_max_packet_size = ep->wMaxPacketSize;
                            }
                            if (dev->output_endpoint == 0 &&
                                is_interrupt && is_output) {
                                /* Use this endpoint for OUTPUT */
                                dev->output_endpoint = ep->bEndpointAddress;
                            }
                        }

                        pthread_create(&dev->thread, NULL, read_thread, dev);

                        /* Wait here for the read thread to be initialized. */
                        pthread_barrier_wait(&dev->barrier);

                    }
                    free(dev_path);
                }
            }
        }
        libusb_free_config_descriptor(conf_desc);

    }

    libusb_free_device_list(devs, 1);

    /* If we have a good handle, return it. */
    if (good_open) {
        return dev;
    }
    else {
        /* Unable to open any devices. */
        free_hid_device(dev);
        return NULL;
    }
}

void ListDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    if (Params().NetworkIDString() == "regtest") {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return;
    }

    struct hid_device_info *devs, *cur_dev;

    if (libusb_init(&usb_context)) {
    //if (hid_init()) {
        return;
    }


    devs = libusb_enumerate();
    cur_dev = devs;
    while (cur_dev) {
        for (const auto &type : usbDeviceTypes) {
            if (cur_dev->vendor_id != type.nVendorId
                || cur_dev->product_id != type.nProductId) {
                continue;
            }

            if (type.type == USBDEVICE_LEDGER_NANO_S
                && MatchLedgerInterface(cur_dev)) {
                std::unique_ptr<CUSBDevice> device(new CLedgerDevice(&type, cur_dev->path, (char*)cur_dev->serial_number, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            } else
            if (type.type == USBDEVICE_TREZOR_ONE
                && MatchTrezorInterface(cur_dev)) {
                std::unique_ptr<CUSBDevice> device(new CTrezorDevice(&type, cur_dev->path, (char*)cur_dev->serial_number, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            }
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);

    //hid_exit();
    if (usb_context) {
        libusb_exit(usb_context);
        usb_context = NULL;
    }

    return;
};

CUSBDevice *SelectDevice(std::vector<std::unique_ptr<CUSBDevice> > &vDevices, std::string &sError)
{
    if (Params().NetworkIDString() == "regtest") {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return vDevices[0].get();
    }

    ListDevices(vDevices);
    if (vDevices.size() < 1) {
        sError = "No device found.";
        return nullptr;
    }
    if (vDevices.size() > 1) { // TODO: Select device
        sError = "Multiple devices found.";
        return nullptr;
    }

    return vDevices[0].get();
};

DeviceSignatureCreator::DeviceSignatureCreator(CUSBDevice *pDeviceIn, const CMutableTransaction *txToIn,
    unsigned int nInIn, const std::vector<uint8_t> &amountIn, int nHashTypeIn)
    : BaseSignatureCreator(), txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn), pDevice(pDeviceIn)
{
};

bool DeviceSignatureCreator::CreateSig(const SigningProvider& provider, std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode, SigVersion sigversion) const
{
    if (!pDevice) {
        return false;
    }

    //uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);

    const CHDWallet *pw = dynamic_cast<const CHDWallet*>(&provider);
    if (pw) {
        const CEKAKey *pak = nullptr;
        const CEKASCKey *pasc = nullptr;
        CExtKeyAccount *pa = nullptr;
        if (!pw->HaveKey(keyid, pak, pasc, pa) || !pa) {
            return false;
        }

        std::vector<uint32_t> vPath;
        std::vector<uint8_t> vSharedSecret;
        if (pak) {
            if (!pw->GetFullChainPath(pa, pak->nParent, vPath)) {
                return error("%s: GetFullAccountPath failed.", __func__);
            }

            vPath.push_back(pak->nKey);
        } else
        if (pasc) {
            AccStealthKeyMap::const_iterator miSk = pa->mapStealthKeys.find(pasc->idStealthKey);
            if (miSk == pa->mapStealthKeys.end()) {
                return error("%s: CEKASCKey Stealth key not found.", __func__);
            }
            if (!pw->GetFullChainPath(pa, miSk->second.akSpend.nParent, vPath)) {
                return error("%s: GetFullAccountPath failed.", __func__);
            }

            vPath.push_back(miSk->second.akSpend.nKey);
            vSharedSecret.resize(32);
            memcpy(vSharedSecret.data(), pasc->sShared.begin(), 32);
        } else {
            return error("%s: HaveKey error.", __func__);
        }
        if (0 != pDevice->SignTransaction(vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->sError)) {
            return error("%s: SignTransaction failed.", __func__);
        }
        return true;
    }

    const CPathKeyStore *pks = dynamic_cast<const CPathKeyStore*>(&provider);
    if (pks) {
        CPathKey pathkey;
        if (!pks->GetKey(keyid, pathkey)) {
            return false;
        }

        std::vector<uint8_t> vSharedSecret;
        if (0 != pDevice->SignTransaction(pathkey.vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->sError)) {
            return error("%s: SignTransaction failed.", __func__);
        }
        return true;
    }

    return false;
};

} // usb_device
