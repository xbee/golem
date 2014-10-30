from examples.gnr.ui.EnvironmentsDialog import EnvironmentsDialog
from examples.gnr.ui.EnvTableElem import EnvTableElem
from PyQt4 import QtCore
from PyQt4.QtGui import QTableWidgetItem

import logging

logger = logging.getLogger(__name__)

class EnvironmentsDialogCustomizer:
    #############################
    def __init__( self, gui, logic ):

        assert isinstance( gui, EnvironmentsDialog )

        self.gui    = gui
        self.logic  = logic

        self.__init()
        self.__setupConnections()

    #############################
    def __init( self ):
        self.gui.ui.tableWidget.horizontalHeader().setStretchLastSection( True )
        self.environments = self.logic.getEnvironments()
        for env in self.environments:
            currentRowCount = self.gui.ui.tableWidget.rowCount()
            self.gui.ui.tableWidget.insertRow( currentRowCount )

            envTableElem = EnvTableElem( env.getId(), self.__printSupported( env.supported() ), env.shortDescription  )
            for col in range( 0, 3 ):
                self.gui.ui.tableWidget.setItem(currentRowCount, col, envTableElem.getColumnItem( col ) )

    def __printSupported( self, val ):
        if val:
            return "Supported"
        else:
            return "Not supported"

    #############################
    def __setupConnections( self ):
        self.gui.ui.okButton.clicked.connect( self.gui.close )
        QtCore.QObject.connect( self.gui.ui.tableWidget, QtCore.SIGNAL( "cellClicked(int, int)" ), self.__taskTableRowClicked )

    def __taskTableRowClicked( self, row, col ):
        if row < self.gui.ui.tableWidget.rowCount():
            envId = self.gui.ui.tableWidget.item( row, 0 ).text()
            env = self.__getEnv( envId )
            if env:
                self.gui.ui.envTextBrowser.setText( env.description()  )

    def __getEnv( self, id ):
        for env in self.environments:
            if env.getId() == id:
                return env
        return None