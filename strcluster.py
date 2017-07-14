# (C) Copyright 2017 Comsecuris UG
# --------------------------------
# This plugin extends IDA Pro's capabilities to display strings within the binary
# by clustering found strings on a per-function basis. Strings that don't belong
# to a function are grouped into the 0_sub pseudo-function. This allows to quickly
# identify intersting functionality as well as strings that are not part of a function
# and quickly navigate through the results and filter them, hopefully making manual
# analysis more effectively.

import re

import idautils
import idc
import idaapi
from idaapi import PluginForm

import time

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

DEBUG         = False
PROFILE       = False
NO_FUNC       = '0_sub'
MATCH_COLOR   = QColor(0xC7,0xF2, 0xCF)
NOMATCH_COLOR = QColor('white')

FUN_COLUMN    = 0
XREF_COLUMN   = 1
STR_COLUMN    = 2

if PROFILE == True:
	start_time = time.time()
	import cProfile, pstats, StringIO
	pr = cProfile.Profile()
	pr.enable()

def dprint(s):
	if DEBUG == True:
		print(s)

class StringItem(QStandardItem):
	def __init__(self, s, ea):
		super(QStandardItem, self).__init__(s)
		self.ea = ea

class IdaString():
	def __init__(self, s, ea, xref):
		self.s = s
		self.ea = ea
		self.xref = xref

class StringClusterMap(PluginForm):
	def getIcon(self):
		icon = (
			'0000010001001010000001002000680400001600000028000000100000002000000001'
			'0020000000000000040000130b0000130b00000000000000000000000000000773e600'
			'0577df000877dd060477df490277e0a70277e0e30277e0fb0277e0fb0277e0e30277e0'
			'a70377e0490577e0060377e1000175f00000000000000000000377e0000577df180377'
			'e0920277e0ed0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0277e0ed02'
			'77e0920377e1180277e100000000000577df000577df180277e0b10177e0ff0177e0ff'
			'0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0277e0'
			'b10377e1180377e1000174de070176df920076e0ff0077e0ff0177e0ff0177e0ff0177'
			'e0ff0076e0ff0076e0ff0177e0ff0177e0ff0177e0ff0077e0ff0076e0ff0176e09202'
			'76e107127fe0481983e2ee1f87e3ff0d7de1ff0076e0ff0077e0ff067ae1ff1d86e3ff'
			'1a84e3ff077ae1ff0177e0ff0076e0ff0e7ee1ff1e87e3ff1581e2ee0a7be1483592e4'
			'a759a6e9ff4fa0e8ff66adeaff1e86e3ff0b7ce1ff60a9e9ff57a5e9ff56a4e9ff459b'
			'e7ff0277e0ff288ce4ff68aeeaff51a1e8ff56a4e8ff2389e3a70578e0e40177e0ff00'
			'72dfff499de7ff4fa1e8ff3c96e6ff53a3e8ff0074dfff0075e0ff0579e0ff0478e0ff'
			'6cb0ebff268be4ff0075e0ff0378e0ff0478e0e40176e0fb1481e2ff439ae7ff7bb8ec'
			'ff2a8ce4ff5da8eaff63abeaff3793e5ff3894e6ff3392e5ff1481e2ff73b4edff0b7c'
			'e1ff0177e0ff0177e0ff0277e0fb2c8de4fb76b5ecff50a1e8ff1e86e3ff0075e0ff59'
			'a6e9ff63abeaff3692e5ff3793e5ff76b5ecff2389e3ff73b4ecff0d7de1ff0077e0ff'
			'0077e0ff0177e0fb5ea8e9e455a4e8ff0075e0ff0b7ce1ff0679e0ff3090e5ff59a6e9'
			'ff0377e0ff1380e2ff62abe9ff0c7ce1ff65aceaff3693e5ff0478e0ff0d7de1ff077a'
			'e1e42489e2a75ba7e9ff59a5e9ff5aa6e9ff1983e2ff0578e0ff489de7ff5da8eaff5f'
			'a9eaff2c8ee4ff0075e0ff1a84e2ff60aaeaff5ba6e9ff57a4e9ff1f86e3a70075df48'
			'0478e0ee0e7ee1ff087be1ff0177e0ff0177e0ff0177e0ff0c7de1ff087be1ff0076e0'
			'ff0177e0ff0076e0ff0479e0ff0e7ee1ff087ae1ee0377e0480777de070377e0920177'
			'e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff01'
			'77e0ff0177e0ff0177e0ff0277e0920477e1070577df000577df180277e0b10177e0ff'
			'0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0'
			'ff0277e0b10377e1180377e100000000000377e0000577df180377e0920277e0ed0177'
			'e0ff0177e0ff0177e0ff0177e0ff0177e0ff0177e0ff0277e0ed0277e0920377e11802'
			'77e10000000000000000000773e6000577df000877dd060477df490277e0a70277e0e3'
			'0277e0fb0277e0fb0277e0e30277e0a70377e0490676e0060377e1000174f300000000'
			'00e0070000c00300008001000000000000000000000000000000000000000000000000'
			'00000000000000000000000000000000000080010000c0030000e0070000')
		image = QtGui.QImage()
		image.loadFromData(QtCore.QByteArray.fromHex(icon))
		pixmap = QtGui.QPixmap()
		pixmap.convertFromImage(image)
		return QtGui.QIcon(pixmap)

	def OnCreate(self, form):
		self.parent = self.FormToPyQtWidget(form)
		self.items = {}
		self.PopulateForm()

	def xrefsTo(self, ea):
		s = []
		map(lambda x: s.append(x.frm), XrefsTo(ea))
		return s
	
	def funXrefs(self):
		res = {}
		for s in idautils.Strings():
			s_ea = s.ea
			s_v = str(s).rstrip()
			dprint("checking %x - %s" %(s_ea, s_v))
			s_xrefs_eas = self.xrefsTo(s_ea)
			if not s_xrefs_eas:
				dprint("no xref found for %s" %(s_v))
				s_xrefs_eas = [s_ea]
	
			# same string can be xref'ed by more than one function
			for fs_ea in s_xrefs_eas:
				dprint("looking for function of %x" %(fs_ea))

				f_name = GetFunctionName(fs_ea)
				f_ea = GetFunctionAttr(fs_ea, FUNCATTR_START)
				if not f_name or f_name == '': f_name = NO_FUNC
				if f_ea in res:
					res[f_ea]['strings'][s_v] = IdaString(s_v, s_ea, fs_ea)
				else:
					res[f_ea] = dict({
						'name' : f_name,
						'strings' : { s_v : IdaString(s_v, s_ea, fs_ea) }
					})

		return res

	def hideItem(self, item, search_text):
		if search_text ==  "":
			item.setBackground(NOMATCH_COLOR)
			return False

		if search_text != "" and self.filter_regex != None:
			res = self.filter_regex.search(item.text())
			if res:
				item.setBackground(MATCH_COLOR)
				return False
			else:
				item.setBackground(NOMATCH_COLOR)
				return True

		if search_text != "" and search_text.lower() in item.text().lower():
			item.setBackground(MATCH_COLOR)
			return False
		else:
			item.setBackground(NOMATCH_COLOR)
			return True

	def checkBoxEvent(self, event):
		self.filterEvent()

	def filterEvent(self, event = None):
		if event != None:
			QLineEdit.keyReleaseEvent(self.filter_line, event)

		if event and (event.key() != QtCore.Qt.Key_Enter and event.key() != QtCore.Qt.Key_Return):
			return

		search_text = self.filter_line.text()

		if search_text != "" and self.regexckb.isChecked():
			self.filter_regex = re.compile(search_text)
		else:
			self.filter_regex = None

		res_strs = 0
		for idx in xrange(self.model.rowCount()):
			item = self.model.item(idx)
			n_strings = item.rowCount()
			hide = True if search_text != "" else False

			for c_idx in xrange(n_strings):
				hide_row = self.hidecheckb.isChecked()
				c_item1 = item.child(c_idx, XREF_COLUMN)
				c_item2 = item.child(c_idx, STR_COLUMN)

				for i in [item, c_item1, c_item2]:
					if not self.hideItem(i, search_text):
						hide = False
						hide_row = False
						if i is c_item2: # we only want to count strs
							res_strs += 1

				self.view.setRowHidden(c_idx, self.model.indexFromItem(item), hide_row)

			self.view.setRowHidden(idx, QtCore.QModelIndex(), hide)
			if item.text().startswith(NO_FUNC):
				if self.hidenscheckb.isChecked():
					self.view.collapse(self.model.indexFromItem(item))
				else:
					self.view.expand(self.model.indexFromItem(item))

		self.results.setText('%d strings' %(res_strs))

	def doubleClickEvent(self, event):
		index = event.pos()
		try:
			item = self.model.itemFromIndex(self.view.indexAt(event.pos()))
			column = item.column()
			ea = item.ea
		except:
			return

		if ea != -1:
			idc.Jump(ea)

	def PopulateForm(self):
		self.parent.setWindowIcon(self.getIcon())
		# gather data
		if not self.items:
			self.items = self.funXrefs()

		if PROFILE == True:
			print("--- %s seconds ---" % (time.time() - start_time))

		# create layout
		self.layout = QtWidgets.QVBoxLayout()
		self.layout.setContentsMargins(0,0,0,0)
		self.layout.setSpacing(0)
		self.view = QTreeView()
		self.view.setSelectionBehavior(QAbstractItemView.SelectRows)

		self.model = QStandardItemModel()
		self.model.setHorizontalHeaderLabels(['Function', 'Xref EA', 'String'])

		self.view.setModel(self.model)
		self.view.setUniformRowHeights(True)
		res_strs = 0
		parent = None
		for idx, (f_ea, fi) in enumerate(self.items.iteritems()):
			fun_ea = f_ea
			fun_name = fi['name']
			fun_strs = len(fi['strings'])
			res_strs += fun_strs

			parent = StringItem('%s (%d)' %(fun_name, fun_strs), fun_ea)
			parent.setEditable(False)

			for (s_v, s) in fi['strings'].iteritems():
				ilist = [StringItem('', -1), StringItem('%x' %(s.xref), s.xref), StringItem(s_v, s.ea)]
				for i in ilist: i.setEditable(False)
				parent.appendRow(ilist)

			self.model.appendRow(parent)
			# make sure the first column is as large as the function name
			#self.view.setFirstColumnSpanned(idx, self.view.rootIndex(), True)

		index = self.model.indexFromItem(parent)
		self.view.expandAll()
		self.view.resizeColumnToContents(0)

		self.layout.addWidget(self.view)

		self.filterbox = QGroupBox()
		self.ctrlbox = QGroupBox()
		self.filterlayout = QGridLayout()
		self.ctrllayout = QHBoxLayout()
		self.ctrllayout.setContentsMargins(0,0,0,0)
		self.filterlayout.setContentsMargins(0,1,0,0)

		self.filter_line = QLineEdit() #FilterLine()
		self.results = QLabel('%d strings' %(res_strs))
		self.hidecheckb = QCheckBox('Hide no match')
		self.hidenscheckb = QCheckBox('Collapse ' + NO_FUNC)
		self.regexckb = QCheckBox('Regex')
		self.hidecheckb.setChecked(True)
		self.hidenscheckb.setChecked(False)
		self.regexckb.setChecked(False)
		self.filter_regex = None

		self.hidecheckb.stateChanged.connect(self.checkBoxEvent)
		self.hidenscheckb.stateChanged.connect(self.checkBoxEvent)
		self.regexckb.stateChanged.connect(self.checkBoxEvent)
		self.filter_line.keyReleaseEvent = self.filterEvent
		self.view.mouseDoubleClickEvent = self.doubleClickEvent
		self.filterlayout.addWidget(self.filter_line, 1, 1)
		self.filterlayout.addWidget(self.results, 1, 2)
		self.ctrllayout.addWidget(self.hidecheckb)
		self.ctrllayout.addWidget(self.hidenscheckb)
		self.ctrllayout.addWidget(self.regexckb)
		self.ctrllayout.addStretch()

		self.layout.addWidget(self.filterbox)
		self.layout.addWidget(self.ctrlbox)
		self.parent.setLayout(self.layout)
		self.filterbox.setLayout(self.filterlayout)
		self.ctrlbox.setLayout(self.ctrllayout)
		# this is mostly useful for the first column, which forms the parent.
		# other columns can also be sorted, but due to the tree nature remain
		# sorted within their respective parents, which can be confusing at first.
		self.view.setSortingEnabled(True)

		if PROFILE == True:
			print("--- %s seconds ---" % (time.time() - start_time))
			s = StringIO.StringIO()
			sortby = 'cumulative'
			ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
			ps.print_stats()
			print(s.getvalue())

	def OnClose(self, form):
		pass

class ida_string_cluster_plugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_OK
	comment = ""
	help = ""
	wanted_name = "Comsecuris StringCluster"
	wanted_hotkey = "Alt-s"

	def init(self):
		return idaapi.PLUGIN_OK
	
	def run(self, arg):
		plg = StringClusterMap()
		plg.Show("StringCluster")
		return

	def term(self):
		pass


def PLUGIN_ENTRY():
	return ida_string_cluster_plugin()
