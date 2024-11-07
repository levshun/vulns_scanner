## Статистика по записям в БД на 07.11.2024

1) Число полученных CVE

```
vulns_scanner=# select count(*) from cves;

 count  
--------
 176375
(1 row)

```

2) Число CVE по годам

```
select yr, count(yr) from 
(select right(left(cve_id, 8), 4) as yr from cves) t
group by yr
order by yr;

  yr  | count 
------+-------
 1999 |  1400
 2000 |  1225
 2001 |  1476
 2002 |  2298
 2003 |  1435
 2004 |  2606
 2005 |  4559
 2006 |  6841
 2007 |  5924
 2008 |  6368
 2009 |  4168
 2010 |  3903
 2011 |  3612
 2012 |  4596
 2013 |  5329
 2014 |  7377
 2015 |  6190
 2016 |  6739
 2017 | 10729
 2018 | 11295
 2019 | 10421
 2020 | 13902
 2021 | 15485
 2022 | 17611
 2023 | 19401
 2024 |  1484
 cve  |     1
(27 rows)

```

3) Число описаний для CVE

```
vulns_scanner=# select count(*) from descriptions;
 count  
--------
 176374
(1 row)
```

4) Число CPE

```
vulns_scanner=# select count(*) from cpes;
 count  
--------
 731546
(1 row)

```