QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    protocol.cpp \
    sniffer-back.cpp \
    sniffer.cpp

HEADERS += \
    mainwindow.h \
    protocol.h \
    sniffer.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

INCLUDEPATH += "E:/1-apps/qt/WpdPack/Include"
LIBS += "-LE:/1-apps/qt/WpdPack/Lib/x64" -lwpcap -lPacket -lwsock32
