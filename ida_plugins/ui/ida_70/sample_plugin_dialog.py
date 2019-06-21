"""
Sample dialog box UI for IDA 7.0 plugins which lets the user choose between several options
"""
from idaapi import *


def dummy1():
	print('inside dummy1\n')


def dummy2():
	print('inside dummy2\n')


options = [
	('First option', dummy1),
	('Second option', dummy2),
]


def main():
	title = 'My title'

	class MainMenu(Choose):
		def __init__(self):
			Choose.__init__(self, title=title, cols=[["Option", 10]], flags=0x11)

		def OnClose(self):
			pass

		def OnGetLine(self, n):
			return [options[n][0]]

		def OnGetSize(self):
			return len(options)

		def OnSelectLine(self, n):
			f = options[n][1]
			f()
			pass

	menu = MainMenu()
	menu.Show(modal=True)


class MyPlugin(plugin_t):
	flags = PLUGIN_FIX
	comment = 'My Comment'
	help = 'My Help'
	wanted_name = 'My Plugin Name'
	wanted_hotkey = 'Alt-1'

	def init(self):
		return PLUGIN_KEEP

	def run(self, arg):
		main()

	def term(self):
		pass


def PLUGIN_ENTRY():
	return MyPlugin()
