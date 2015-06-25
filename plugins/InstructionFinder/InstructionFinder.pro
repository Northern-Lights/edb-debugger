#-------------------------------------------------
#
# Project created by QtCreator 2015-04-11T15:04:59
#
#-------------------------------------------------
include(../plugins.pri)

#QT       += core gui

#TARGET = InstructionFinder
#TEMPLATE = lib
#CONFIG += plugin

#DESTDIR = $$[QT_INSTALL_PLUGINS]/generic

SOURCES += InstructionFinder.cpp \
    dialoginstructionfinder.cpp

HEADERS += InstructionFinder.h \
    dialoginstructionfinder.h
#OTHER_FILES += InstructionFinder.json

#unix {
#    target.path = /usr/lib
#    INSTALLS += target
#}

FORMS += \
    dialoginstructionfinder.ui
