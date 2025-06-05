## Описание структуры проекта на данный момент

```
├── app #Flask приложение
│   ├── app.py #основная логика
│   ├── pipeline.py #алгоритм поиска и генерации 
│   ├── start_model.py 
│   ├── static
│   │   └── styles.css
│   ├── templates
│   │   └── index.html #htm-код страницы
│   └── utils.py
|
├── backlog.md
├── models #папка отсутствует в репозитории
|          # модели можно найти: BERT -- https://drive.google.com/drive/folders/1Ktf5Pdn8A7FiGBoJ_WFVXLzMcF8AnKW3?usp=drive_link
|          # NuNER -- https://drive.google.com/drive/folders/11I3sNBtts_pe048kaVHpgofQGpXqMIPB?usp=drive_link 
|
|
├── notebooks
│   ├── create_cve_cpe_config.ipynb
│   ├── eda.ipynb
│   ├── eda_versions.ipynb
│   ├── enrich_stucco_dataset.ipynb
│   ├── fuzzy_search_product_name.ipynb
│   ├── make_dataset_manual_annotation.ipynb
│   ├── make_dataset_nuner_old.py
│   ├── make_dataset_nuner_v2.py
│   ├── nuner_as_token_classifier.ipynb #дообучение NER моделей
│   ├── search_and_generate_cpe_using_ner.ipynb 
│   ├── start_model.ipynb
├── README.md
├── runner.py #запуск парсинга feeds 
├── samples
│   ├── cpes_sample.csv
│   ├── cves_sample.csv
│   └── descriptions_sample.csv
├── src
│   ├── db # sql-команды для создания структуры базы данных для работы
│   │   ├── db_commands
│   │   └── db_schemas
│   ├── download_files.py #скрипт для загрузки файлов
│   ├── get_info_from_os.py
│   ├── get_info_scripts_drafts
│   │   ├── draft_system_info_csv_file.csv
│   │   ├── os_apt.py
│   │   ├── os_data.py
│   │   └── os_dpkg.py
│   ├── get_software_info.py #получение данных об ОС и ПО и запись в БД
│   ├── infogetter.py #класс с методами для получения данных об ОС и ПО
│   ├── __init__.py
│   ├── model
│   │   └── start_model.py
│   ├── parse_nisd_feeds.py #набор функций для обработки файлов из CPE JSON feeds
│   ├── run_parser.py #создание папки с файлами, содержащими csv структуры `[cve, cpe, config_id]`
│   ├── utils
│   │   ├── logger.py
│   ├── write_cve_cpe_config_to_db.py #запись CVE и CPE в БД
│   └── write_descriptions_to_db.py #запись описаний CVE в БД
├── statistics.md #базовая описательная статистика
```

