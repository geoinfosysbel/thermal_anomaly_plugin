# -*- coding: utf-8 -*-

# QDraw: plugin that makes drawing easier
# Author: Jérémy Kalsron
#         jeremy.kalsron@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Mainly comes from selectTools.py from Cadre de Permanence by Mederic Ribreux

from qgis.gui import QgsMapTool, QgsRubberBand
from qgis.core import QgsWkbTypes

from qgis.PyQt.QtCore import Qt, pyqtSignal
from qgis.PyQt.QtGui import QKeySequence


class DrawPolygon(QgsMapTool):

    selectionDone = pyqtSignal()
    move = pyqtSignal()

    def __init__(self, iface, color):
        canvas = iface.mapCanvas()
        QgsMapTool.__init__(self, canvas)
        self.canvas = canvas
        self.iface = iface
        self.status = 0
        self.rb = QgsRubberBand(self.canvas, QgsWkbTypes.PolygonGeometry)
        self.rb.setColor(color)
        return None

    def keyPressEvent(self, e):
        if e.matches(QKeySequence.Undo):
            if self.rb.numberOfVertices() > 1:
                self.rb.removeLastPoint()

    def canvasPressEvent(self, e):
        if e.button() == Qt.LeftButton:
            if self.status == 0:
                self.rb.reset(QgsWkbTypes.PolygonGeometry)
                self.status = 1
            self.rb.addPoint(self.toMapCoordinates(e.pos()))
        else:
            if self.rb.numberOfVertices() > 2:
                self.status = 0
                self.selectionDone.emit()
            else:
                self.reset()
        return None

    def canvasMoveEvent(self, e):
        if self.rb.numberOfVertices() > 0 and self.status == 1:
            self.rb.removeLastPoint(0)
            self.rb.addPoint(self.toMapCoordinates(e.pos()))
        self.move.emit()
        return None

    def reset(self):
        self.status = 0
        self.rb.reset(True)

    def deactivate(self):
        self.rb.reset(True)
        QgsMapTool.deactivate(self)
