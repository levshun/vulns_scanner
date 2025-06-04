## Описание структуры проекта на данный момент

```
- data    # Здесь лежат данные
├── cve
│   ├── nvdcve-1.1-2002
│   │   └── nvdcve-1.1-2002.json
|
│   └── nvdcve-1.1-2024
│       └── nvdcve-1.1-2024.json
├── cve_cpe_config_dir
│   ├── nvdcve-1.1-2002.csv
|
│   └── nvdcve-1.1-2024.csv

- notebooks    # Здесь лежат ноутбуки с EDA

- samples     # Здесь лежат примеры данных

- src
├── db      # sql-команды для создания структуры базы данных для работы
│   ├── db_commands    
│   └── db_schemas
├── download_files.py       # скрипт для загрузки файлов
├── get_info_from_os.py
├── get_info_scripts_drafts
│   ├── draft_system_info_csv_file.csv
│   ├── os_apt.py
│   ├── os_data.py
│   └── os_dpkg.py
├── get_software_info.py    # получение данных об ОС и ПО и запись в БД
├── infogetter.py       # класс с методами для получения данных об ОС и ПО
├── parse_nisd_feeds.py         # набор функций для обработки файлов из CPE JSON feeds
├── run_parser.py       # создание папки с файлами, содержащими csv структуры `[cve, cpe, config_id]`
├── utils       
│   ├── logger.py       # логгирование
├── write_cve_cpe_config_to_db.py   # запись CVE и CPE в БД
└── write_descriptions_to_db.py     # запись описаний CVE в БД

- runner.py     # запуск парсинга feeds 

- README.md

- statistics.md     # базовая описательная статистика
```


