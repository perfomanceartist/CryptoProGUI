#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import (QWidget, QToolTip, QMessageBox, QInputDialog,
    QPushButton, QApplication, QCheckBox, QComboBox, QTextEdit, QGroupBox)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import pyqtSlot
import client
import myasn1

class PyCryptoGUI(QWidget):

    def __init__(self):
        super().__init__()        
        self.client = client.Client()
        self.initUI()

    def initUI(self):
        QToolTip.setFont(QFont('SansSerif', 10))

        comboboxCertificates = QComboBox(self)
        comboboxCertificates.setGeometry(10, 10, 200, 30)
  
        certificatesNames = self.getCertificatesNames()
  
        # adding list of items to combo box
        comboboxCertificates.addItems(certificatesNames)

        textbox = QTextEdit(self)
        textbox.setGeometry(10, 50, 200, 100)

        groupboxParams = QGroupBox('Параметры', self)
        groupboxParams.setGeometry(220, 50, 150, 100)


        checkboxEncrypt = QCheckBox('Зашифровать', groupboxParams)
        checkboxEncrypt.setGeometry(10, 20, 120, 50)

        checkboxSign = QCheckBox('Подписать', groupboxParams)
        checkboxSign.setGeometry(10, 50, 120, 50)

        btnHash = QPushButton('Вычислить хеш', self)
        btnHash.move(10, 160)
        btnHash.clicked.connect(self.printHash)

        btnSend = QPushButton('Отправить на сервер', self)
        btnSend.move(220, 15)
        btnSend.clicked.connect(self.sendText)

        btnSave = QPushButton('Сохранить в файл', self)
        btnSave.move(150, 160)
        btnSave.clicked.connect(self.saveToFile)

        self.comboboxCertificates = comboboxCertificates
        self.textbox = textbox
        self.checkboxEncrypt = checkboxEncrypt
        self.checkboxSign = checkboxSign
        


        self.setGeometry(300, 300, 450, 200)
        self.setWindowTitle('Pasoib 9 CryptoPro')
        self.show()

    def getCertificatesNames(self):
        return self.client.getCertificatesNames()

    def operateText(self, need_sign = True, need_encrypt = True, password = None):
        certnum = self.comboboxCertificates.currentIndex() + 1
        data = self.textbox.toPlainText()

        if need_encrypt:        
            encrypted = self.client.EncryptData(data=data, cert=certnum)
        else:
            encrypted = data.encode()
        
        if need_sign:
            signment = self.client.SignData(data=data, cert=certnum, password=password)
        else:
            signment = b'-'
        myasn = myasn1.MyAsn()
        packed = myasn.encode(encrypted, signment, encryptedFlag=need_encrypt)
        return packed

    @pyqtSlot()
    def printHash(self):
        data = self.textbox.toPlainText()
        b64hash = self.client.HashData(data).Value
        QMessageBox.about(self, "Значения хеша", f"Ваше значение хеша:{b64hash}")

    @pyqtSlot()
    def saveToFile(self):
        need_sign = self.checkboxSign.isChecked()
        need_encrypt = self.checkboxEncrypt.isChecked()
        password = None
        if need_sign:
            password, ok = QInputDialog.getText(self, 'Запрос пароля', 'Введите пароль для доступа к закрытому ключу')
            if not ok:
                return
        
        try:
            operated = self.operateText(need_sign, need_encrypt, password=password)
        except:
            QMessageBox.about(self, "Ошибка!", "Не удалось подписать текст. Скорее всего, введен неверный пароль.")
            return

        filename, ok = QInputDialog.getText(self, 'Имя файла для сохранения', 'Введите имя файла', text='result.bin')
        if not ok:
            return
        with open(filename, "wb") as f:
            f.write(operated)
        QMessageBox.about(self, "Сообщение", "Файл сохранен.")


    @pyqtSlot()
    def sendText(self):    
        if self.client.Connect() is False:
            QMessageBox.about(self, "Ошибка", "Не удается подключиться к серверу")
            return

        need_sign = self.checkboxSign.isChecked()
        need_encrypt = self.checkboxEncrypt.isChecked()
        
        password = None
        if need_sign:
            password, ok = QInputDialog.getText(self, 'Запрос пароля', 'Введите пароль для доступа к закрытому ключу')
            if not ok:
                return
        operated = self.operateText(need_sign, need_encrypt, password=password)

        answer = self.client.SendData(operated)
        QMessageBox.about(self, "Ответ сервера", answer)


if __name__ == '__main__':
    custom_font = QFont()
    custom_font.setWeight(10)
    QApplication.setFont(custom_font, "QLabel")
    
    app = QApplication(sys.argv)
    gui = PyCryptoGUI()
    sys.exit(app.exec_())
    
