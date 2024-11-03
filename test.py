from mitmproxy import http
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# 配置 Selenium Chrome 瀏覽器無頭模式
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")

# 初始化 Selenium 瀏覽器
driver = webdriver.Chrome(options=chrome_options)
a=1