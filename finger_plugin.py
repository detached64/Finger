# -*- coding: utf8 -*-
# Original Author: github@aliyunav
# Original Source: https://github.com/aliyunav/Finger
# Modified by: github@detached64

import idc
import idaapi
import idautils
import traceback
from finger_sdk import client, ida_func

class FingerManager:
    def __init__(self):
        self.url = "https://sec-lab.aliyun.com/finger/recognize/"
        self.headers = {'content-type': 'application/json'}
        self.timeout = 5
        self.client = None

    def fetch_function_symbol(self, start_ea):
        func_symbol = None
        try:
            self.client = client.Client(self.url, self.headers, self.timeout)
            func_feat = ida_func.get_func_feature(start_ea)
            if func_feat:
                func_id, res = self.client.recognize_function(func_feat)
                if res and res[func_id]:
                    func_symbol = res[func_id]
        except Exception as e:
            print(traceback.format_exc())
        if func_symbol:
            func_symbol = str(func_symbol)  # python2 unicode to str
        return func_symbol

    def recognize_function(self):
        ea = idaapi.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if pfn:
            func_name = idc.get_func_name(pfn.start_ea)
            func_symbol = self.fetch_function_symbol(pfn.start_ea)
            if func_symbol:
                #idc.set_color(pfn.start_ea, idc.CIC_FUNC, 0x98FF98)
                idaapi.set_name(pfn.start_ea, func_symbol, idaapi.SN_FORCE)
                idaapi.update_func(pfn)
                print("[+]%s -> %s" %(func_name, func_symbol))
            else:
                print("[-]%s recognize failed." %(func_name))
        else:
            print("[-]0x%x is not a function." %ea)

    def recognize_selected_functions(self, funcs):
        count = 0
        for pfn in funcs:
            func_name = idc.get_func_name(pfn.start_ea)
            func_symbol = self.fetch_function_symbol(pfn.start_ea)
            if func_symbol:
                #idc.set_color(pfn.start_ea, idc.CIC_FUNC, 0x98FF98)
                idaapi.set_name(pfn.start_ea, func_symbol, idaapi.SN_FORCE)
                idaapi.update_func(pfn)
                print("[+]%s -> %s" %(func_name, func_symbol))
                count += 1
            else:
                print("[-]%s recognize failed." %(func_name))
        print("[+]%d among %d recognized successfully." %(count, len(list(funcs))))

    def recognize_unknown_functions(self):
        func = []
        for ea in idautils.Functions():
            if idc.get_func_name(ea).startswith("sub_"):
                func.append(idaapi.get_func(ea))
        self.recognize_selected_functions(func)

    def recognize_all_functions(self):
        funcs = []
        for ea in idautils.Functions():
            funcs.append(idaapi.get_func(ea))
        self.recognize_selected_functions(funcs)


class FingerUIManager:
    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeSelected", "Finger/")
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeUnknown", "Finger/")
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeAll", "Finger/")
            if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM or idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeFunction", "Finger/")
                idaapi.attach_action_to_popup(widget, popup, "Finger:RecognizeAll", "Finger/")

    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback,  menupath=None):
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            self.callback(ctx)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def __init__(self, name):
        self.name = name
        self.mgr = FingerManager()
        self.hooks = FingerUIManager.UIHooks()

    def register_actions(self):
        rec = FingerUIManager.ActionHandler("Finger:RecognizeFunction", "Recognize this function", "")
        rec.register_action(self.function_callback)
        rec = FingerUIManager.ActionHandler("Finger:RecognizeSelected", "Recognize selected functions", "")
        rec.register_action(self.selected_functions_callback)
        rec = FingerUIManager.ActionHandler("Finger:RecognizeUnknown", "Recognize unknown functions", "")
        rec.register_action(self.unknown_functions_callback)
        rec = FingerUIManager.ActionHandler("Finger:RecognizeAll", "Recognize all functions", "")
        rec.register_action(self.all_functions_callback)
        self.hooks.hook()
        return True

    def function_callback(self, ctx):
        if ctx.action == "Finger:RecognizeFunction":
            self.mgr.recognize_function()

    def selected_functions_callback(self, ctx):
        funcs = list(map(idaapi.getn_func, ctx.chooser_selection))
        if ctx.action == "Finger:RecognizeSelected":
            self.mgr.recognize_selected_functions(funcs)

    def unknown_functions_callback(self, ctx):
        if ctx.action == "Finger:RecognizeUnknown":
            self.mgr.recognize_unknown_functions()

    def all_functions_callback(self, ctx):
        if ctx.action == "Finger:RecognizeAll":
            self.mgr.recognize_all_functions()

def check_ida_version():
    if idaapi.IDA_SDK_VERSION < 700:
        print("[-]Finger support 7.x IDA, please update your IDA version.")
        return False
    return True

class FingerPlugin(idaapi.plugin_t):
    wanted_name = "Finger"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MOD

    def init(self):
        if check_ida_version():
            #idaapi.msg("[+]Finger plugin starts\n")
            manager = FingerUIManager(FingerPlugin.wanted_name)
            if manager.register_actions():
                return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return FingerPlugin()
