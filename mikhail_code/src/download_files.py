import requests
import os
from zipfile import ZipFile 
# https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip

# Загрузка файлов CVE в ./cve/downloaded/year, а затем распаковка в 
# ./cve/year


def download_file(base, file_name, type):
    url = base + file_name
    response = requests.get(url)
    if not os.path.exists(f"./{type}/"):
        os.mkdir(f"./{type}")
        os.mkdir(f"./{type}/downloaded")
    # записываем в zip файл
    with open(f"./{type}/downloaded/" + file_name, mode="wb") as file:
        file.write(response.content)
    # un
    with ZipFile(f"./{type}/downloaded/" + file_name, 'r') as zip_obj:
        zip_obj.extractall(f"./{type}/" + file_name.rstrip(".json.zip"))
    # delete zip
    for item in os.listdir(f"./{type}/downloaded/"):
        os.remove(f"./{type}/downloaded/" + item)
    return 'Done!'

base="https://nvd.nist.gov/feeds/json/cve/1.1/"

for year in range(2002, 2025):
    file_name=f"nvdcve-1.1-{year}.json.zip"
    print(f"Downloading year {year}")
    download_file(base, file_name, "cve")