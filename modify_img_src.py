from mitmproxy import http
from bs4 import BeautifulSoup

def response(flow: http.HTTPFlow):
    # 檢查回應是否為圖片類型


    # 檢查是否為 Chrome 的 User-Agent 並且內容類型是 HTML
    if "text/html" in flow.response.headers.get("Content-Type", "") and "Chrome" in flow.request.headers.get("User-Agent", ""):
        # 使用 BeautifulSoup 解析 HTML
        soup = BeautifulSoup(flow.response.text, "html.parser")
        # 修改所有 <img> 標籤的 src 屬性
        for img in soup.find_all("img"):
            img['src'] = "https://i.natgeofe.com/n/548467d8-c5f1-4551-9f58-6817a8d2c45e/NationalGeographic_2572187_square.jpg"  # 新的圖片 URL
        # 修改所有 <a> 標籤的 href 屬性
        for a in soup.find_all("a"):
            a['href'] = "https://i.natgeofe.com/n/548467d8-c5f1-4551-9f58-6817a8d2c45e/NationalGeographic_2572187_square.jpg"
        # 將修改後的 HTML 轉回給回應
        flow.response.text = str(soup)

