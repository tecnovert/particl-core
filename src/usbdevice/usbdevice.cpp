// Copyright (c) 2018-2025 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <usbdevice/usbdevice.h>

#include <chainparams.h>
#include <common/args.h>
#include <key/extkey.h>
#include <univalue.h>
#include <usbdevice/debugdevice.h>
#include <usbdevice/ledgerdevice.h>
#include <usbdevice/trezordevice.h>
#include <usbdevice/usbwrapper.h>
#ifdef ENABLE_WALLET
#include <wallet/hdwallet.h>
#endif

#include <hidapi/hidapi.h>

#include <stdint.h>

#include <google/protobuf/stubs/common.h>

namespace usb_device {

const DeviceType usbDeviceTypes[] = {
    DeviceType(0xffff, 0x0001, "Debug",     "Device",       USBDEVICE_DEBUG),
    DeviceType(0x2c97, 0x0000, "Ledger",    "Blue",         USBDEVICE_LEDGER_BLUE),
    DeviceType(0x2c97, 0x0001, "Ledger",    "Nano S",       USBDEVICE_LEDGER_NANO_S),
    DeviceType(0x2c97, 0x1015, "Ledger",    "Nano S 1.6",   USBDEVICE_LEDGER_NANO_S),
    DeviceType(0x2c97, 0x0004, "Ledger",    "Nano X",       USBDEVICE_LEDGER_NANO_X),
    DeviceType(0x2c97, 0x4015, "Ledger",    "Nano X 1.6",   USBDEVICE_LEDGER_NANO_X),
    //DeviceType(0x2c97, 0x5015, "Ledger",    "Nano S Plus",  USBDEVICE_LEDGER_NANO_S_PLUS),  TODO: Fix sending bug
    //DeviceType(0x534c, 0x0001, "Trezor", "One", USBDEVICE_TREZOR_ONE),
};

const DeviceType webusbDeviceTypes[] = {
    DeviceType(0x1209, 0x53c1, "Trezor", "One", USBDEVICE_TREZOR_ONE),
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

void ListHIDDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    if (Params().GetChainType() == ChainType::REGTEST &&
        gArgs.GetBoolArg("-debugdevice", true)) {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return;
    }

    struct hid_device_info *devs, *cur_dev;

    if (hid_init()) {
        return;
    }

    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->serial_number) // Possibly no access permission, check udev rules.
        for (const auto &type : usbDeviceTypes) {
            if (cur_dev->vendor_id != type.nVendorId ||
                cur_dev->product_id != type.nProductId) {
                continue;
            }

            if ((type.type == USBDEVICE_LEDGER_BLUE ||
                 type.type == USBDEVICE_LEDGER_NANO_S ||
                 type.type == USBDEVICE_LEDGER_NANO_X ||
                 type.type == USBDEVICE_LEDGER_NANO_S_PLUS) &&
                MatchLedgerInterface(cur_dev)) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CLedgerDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            } else
            if (type.type == USBDEVICE_TREZOR_ONE &&
                MatchTrezorInterface(cur_dev)) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CTrezorDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            }
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);

    hid_exit();

    return;
};

void ListWebUSBDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    struct webusb_device_info *devs, *cur_dev;
    if (webusb_init()) {
        return;
    }

    devs = webusb_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->serial_number) // Possibly no access permission, check udev rules.
        for (const auto &type : webusbDeviceTypes) {
            if (cur_dev->vendor_id != type.nVendorId ||
                cur_dev->product_id != type.nProductId) {
                continue;
            }

            if (type.type == USBDEVICE_TREZOR_ONE &&
                cur_dev->interface_number == 0) {
                char mbs[128];
                wcstombs(mbs, cur_dev->serial_number, sizeof(mbs));
                std::unique_ptr<CUSBDevice> device(new CTrezorDevice(&type, cur_dev->path, mbs, cur_dev->interface_number));
                vDevices.push_back(std::move(device));
            }
        }
        cur_dev = cur_dev->next;
    }
    webusb_free_enumeration(devs);

    webusb_exit();

    return;
};

void ListAllDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices)
{
    if (Params().GetChainType() == ChainType::REGTEST &&
        gArgs.GetBoolArg("-debugdevice", true)) {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return;
    }

    ListHIDDevices(vDevices);
    ListWebUSBDevices(vDevices);

    return;
};

CUSBDevice *SelectDevice(std::vector<std::unique_ptr<CUSBDevice> > &vDevices, std::string &sError)
{
    if (Params().GetChainType() == ChainType::REGTEST &&
        gArgs.GetBoolArg("-debugdevice", true)) {
        vDevices.push_back(std::unique_ptr<CUSBDevice>(new CDebugDevice()));
        return vDevices[0].get();
    }

    ListAllDevices(vDevices);
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
    : BaseSignatureCreator(), txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn, MissingDataBehavior::FAIL), pDevice(pDeviceIn)
{
};

bool DeviceSignatureCreator::CreateSig(const SigningProvider &provider, std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode, SigVersion sigversion) const
{
    if (!pDevice) {
        return false;
    }

    const LegacyScriptPubKeyMan *pkm = dynamic_cast<const LegacyScriptPubKeyMan*>(&provider);
    if (pkm) {
        //uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
        const CHDWallet *pw = dynamic_cast<const CHDWallet*>(&pkm->m_storage);
        if (pw) {
            const CEKAKey *pak = nullptr;
            const CEKASCKey *pasc = nullptr;
            CExtKeyAccount *pa = nullptr;
            {
                LOCK(pw->cs_wallet);
                if (!pw->HaveKey(keyid, pak, pasc, pa) || !pa) {
                    return false;
                }
            }

            std::vector<uint32_t> vPath;
            std::vector<uint8_t> vSharedSecret;
            if (pak) {
                LOCK(pw->cs_wallet);
                if (!pw->GetFullChainPath(pa, pak->nParent, vPath)) {
                    LogError("%s: GetFullAccountPath failed.", __func__);
                    return false;
                }

                vPath.push_back(pak->nKey);
            } else
            if (pasc) {
                AccStealthKeyMap::const_iterator miSk = pa->mapStealthKeys.find(pasc->idStealthKey);
                if (miSk == pa->mapStealthKeys.end()) {
                    LogError("%s: CEKASCKey Stealth key not found.", __func__);
                    return false;
                }
                {
                    LOCK(pw->cs_wallet);
                    if (!pw->GetFullChainPath(pa, miSk->second.akSpend.nParent, vPath)) {
                        LogError("%s: GetFullAccountPath failed.", __func__);
                        return false;
                    }
                }

                vPath.push_back(miSk->second.akSpend.nKey);
                vSharedSecret.resize(32);
                memcpy(vSharedSecret.data(), pasc->sShared.begin(), 32);
            } else {
                LogError("%s: HaveKey error.", __func__);
                return false;
            }
            if (0 != pDevice->SignTransaction(vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->m_error)) {
                LogError("%s: SignTransaction failed.", __func__);
                return false;
            }
            return true;
        }
    }

    const CPathKeyStore *pks = dynamic_cast<const CPathKeyStore*>(&provider);
    if (pks) {
        CPathKey pathkey;
        if (!pks->GetKey(keyid, pathkey)) {
            return false;
        }

        std::vector<uint8_t> vSharedSecret;
        if (0 != pDevice->SignTransaction(pathkey.vPath, vSharedSecret, txTo, nIn, scriptCode, nHashType, amount, sigversion, vchSig, pDevice->m_error)) {
            LogError("%s: SignTransaction failed.", __func__);
            return false;
        }
        return true;
    }

    return false;
}

bool DeviceSignatureCreator::CreateSchnorrSig(const SigningProvider& provider, std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256* leaf_hash, const uint256* merkle_root, SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);

    LogError("%s: TODO.", __func__);
    return false;
}

} // usb_device
