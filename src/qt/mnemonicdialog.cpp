// Copyright (c) 2017-2024 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <qt/mnemonicdialog.h>
#include <qt/forms/ui_mnemonicdialog.h>
#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key/extkey.h>
#include <key/mnemonic.h>
#include <rpc/rpcutil.h>
#include <util/any.h>

#include <QDebug>

void RPCThread::run()
{
    bool passed = false;
    auto context = util::AnyPtr<node::NodeContext>(&m_node);
    CallRPCVoidRv(m_command.toStdString(), context, m_wallet.toStdString(), &passed, m_rv, true);
    Q_EMIT complete(passed);  // Can't pass back a UniValue or signal won't get detected ?
}

MnemonicDialog::MnemonicDialog(QWidget *parent, WalletModel *wm) :
    QDialog(parent), walletModel(wm),
    ui(new Ui::MnemonicDialog)
{
    setWindowFlags(Qt::Window | Qt::WindowTitleHint | Qt::CustomizeWindowHint);
    ui->setupUi(this);

    QObject::connect(ui->btnCancel2, &QPushButton::clicked, this, &MnemonicDialog::on_btnCancel_clicked);
    QObject::connect(ui->btnCancel3, &QPushButton::clicked, this, &MnemonicDialog::on_btnCancel_clicked);

    QObject::connect(this, &MnemonicDialog::startRescan, walletModel, &WalletModel::startRescan, Qt::QueuedConnection);

    setWindowTitle(QString("HD Wallet Setup - %1").arg(QString::fromStdString(wm->wallet().getWalletName())));
    ui->edtPath->setPlaceholderText(tr("Path to derive account from, if not using default. (optional, default=%1)").arg(QString::fromStdString(GetDefaultAccountPath())));
    ui->edtPassword->setPlaceholderText(tr("Enter a passphrase to protect your Recovery Phrase. (optional)"));
#if QT_VERSION >= 0x050200
    ui->tbxMnemonic->setPlaceholderText(tr("Enter your BIP39 compliant Recovery Phrase/Mnemonic."));
#endif

#if ENABLE_USBDEVICE
#else
    ui->tabWidget->setTabEnabled(2, false);
#endif

    if (!wm->wallet().isDefaultAccountSet()) {
        ui->lblHelp->setText(QString(
            "Wallet %1 has no HD account loaded.\n"
            "An account must first be loaded in order to generate receiving addresses.\n"
            "Importing a recovery phrase will load a new master key and account.\n"
            "You can generate a new recovery phrase from the 'Create' page below.\n").arg(QString::fromStdString(wm->wallet().getWalletName())));
    } else {
        ui->lblHelp->setText(QString(
            "Wallet %1 already has an HD account loaded.\n"
            "By importing another recovery phrase a new account will be created and set as the default.\n"
            "The wallet will receive on addresses from the new and existing account/s.\n"
            "New addresses will be generated from the new account.\n").arg(QString::fromStdString(wm->wallet().getWalletName())));
    }

    ui->cbxLanguage->clear();
    for (int l = 1; l < mnemonic::WLL_MAX; ++l) {
        if (mnemonic::HaveLanguage(l)) {
            ui->cbxLanguage->addItem(mnemonic::mnLanguagesDesc[l], QString(mnemonic::mnLanguagesTag[l]));
        }
    }

    return;
};

MnemonicDialog::~MnemonicDialog()
{
    if (m_thread) {
        m_thread->wait();
        delete m_thread;
    }
};

void MnemonicDialog::on_btnCancel_clicked()
{
    close();
    return;
};

void MnemonicDialog::on_btnImport_clicked()
{
    QString sCommand = (ui->chkImportChain->checkState() == Qt::Unchecked)
        ? "extkeyimportmaster" : "extkeygenesisimport";
    sCommand += " \"" + ui->tbxMnemonic->toPlainText() + "\"";

    QString sPassword = GUIUtil::particl::escapeQString(ui->edtPassword->text());
    sCommand += " \"" + sPassword + "\" false \"Master Key\" \"Default Account\" -1";

    UniValue rv;
    if (walletModel->tryCallRpc(sCommand, rv)) {
        close();
        if (!rv["warnings"].isNull()) {
            for (size_t i = 0; i < rv["warnings"].size(); ++i) {
                walletModel->warningBox(tr("Import"), QString::fromStdString(rv["warnings"][i].get_str()));
            }
        }
        startRescan();
    }

    return;
};

void MnemonicDialog::on_btnGenerate_clicked()
{
    int bytes_entropy = ui->spinEntropy->value();
    QString language = ui->cbxLanguage->itemData(ui->cbxLanguage->currentIndex()).toString();

    QString sCommand = "mnemonic new  \"\" " + language + " " + QString::number(bytes_entropy);

    UniValue rv;
    if (walletModel->tryCallRpc(sCommand, rv)) {
        ui->tbxMnemonicOut->setText(QString::fromStdString(rv["mnemonic"].get_str()));
    }

    return;
};

void MnemonicDialog::on_btnImportFromHwd_clicked()
{
    if (m_thread) {
        qWarning() << "MnemonicDialog hwd thread exists.";
        return;
    }
    QString sCommand = "initaccountfromdevice \"From Hardware Device\"";

    QString sPath = ui->edtPath->text();
    sCommand += " \"" + sPath + "\" true -1";

    ui->tbxHwdOut->appendPlainText("Waiting for device.");
    setEnabled(false);

    m_thread = new RPCThread(sCommand, walletModel->m_node, walletModel->getWalletName(), &m_rv);
    connect(m_thread, &RPCThread::complete, this, &MnemonicDialog::hwImportComplete);
    m_thread->setObjectName("particl-hwImport");
    m_thread->start();

    return;
};

void MnemonicDialog::hwImportComplete(bool passed)
{
    setEnabled(true);

    m_thread->wait();
    delete m_thread;
    m_thread = nullptr;

    if (!passed) {
        QString sError;
        if (m_rv["Error"].isStr()) {
            sError = QString::fromStdString(m_rv["Error"].get_str());
        } else {
            sError = QString::fromStdString(m_rv.write(1));
        }

        ui->tbxHwdOut->appendPlainText(sError);
        if (sError == "No device found."
            || sError.indexOf("6982") > -1) {
#ifndef WIN32
#ifndef MAC_OSX
            ui->tbxHwdOut->appendPlainText("Have you added a udev rule for your device?");
#endif
#endif
            ui->tbxHwdOut->appendPlainText("The Particl app on your device must be open before importing.");
        }
    } else {
        UniValue rv;
        QString sCommand = "devicegetnewstealthaddress \"default stealth\"";
        walletModel->tryCallRpc(sCommand, rv);
        close();

        startRescan();
    }

    return;
};
