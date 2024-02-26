# Backlog

## To-do

* Добавить CVSS-2

Для некоторых CPE нет информации о CVSS-3, поэтому необходимо учитывать CVSS-2

* Добавить явно версии продукта в CPE 

Добавить в промежуточную таблицу `CPE_CVE_Config` версии отдельными столбцами, поскольку в нынешней версии не у всех CPE явно хранятся промежуточные версии. Например, в случае
```
[
{'cpe23Uri': 'cpe:2.3:a:abb:platform_engineering_tools:*:*:*:*:*:*:*:*', 
'versionStartIncluding': '1.0.0', 
'versionEndIncluding': '2.3.0', 
'cpe_name': 
    [{'cpe23Uri': 'cpe:2.3:a:abb:platform_engineering_tools:1.0.0:*:*:*:*:*:*:*'}, 
     {'cpe23Uri': 'cpe:2.3:a:abb:platform_engineering_tools:2.3.0:*:*:*:*:*:*:*'}
    ]
}
]
``` 

## In progress


## Done