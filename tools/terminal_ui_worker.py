"""终端 UI 自动化 worker（使用 ces_UI_auto 的 Selenium Page Object）。"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
from runner import public_config as _pub
import json
import os
import sys
UI_ROOT = 'configured-path'
sys.path.insert(0, UI_ROOT)
os.chdir(UI_ROOT)
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from conf.conf import ConfigManager
from pages.Index_Page.index import LoginPage
from pages.ContactList_Page.TerminalPage import TerminalManagerPage

def main():
    name = sys.argv[1]
    serial = sys.argv[2]
    opts = webdriver.ChromeOptions()
    opts.add_argument('--headless=new')
    opts.add_argument('--ignore-certificate-errors')
    opts.add_argument('--window-size=1600,950')
    driver = webdriver.Chrome(service=Service(ConfigManager.CHROMEDRIVER_PATH), options=opts)
    out = {'login': False, 'add': False, 'xss': 0, 'cleanup': False, 'body': ''}
    try:
        lp = LoginPage(driver=driver)
        lp.open_login_url()
        out['login'] = bool(lp.common_login())
        tp = TerminalManagerPage(driver=driver)
        tp.common_enter_terminal()
        out['add'] = bool(tp.add_terminal(name, serial))
        try:
            body = driver.find_element('css selector', 'body').text
            out['body'] = body[-2000:]
            out['xss'] = driver.execute_script('return window.__xss || 0')
        except Exception:
            pass
        out['cleanup'] = bool(tp.delete_terminal(name))
    except Exception as e:
        out['error'] = str(e)[:300]
    finally:
        try:
            driver.quit()
        except Exception:
            pass
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out['login'] and out['add'] and out['cleanup'] else 1
if __name__ == '__main__':
    sys.exit(main())
