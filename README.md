Tracer of Autonomous Systems
============================

Описание проекта
----------------

Tracer of Autonomous Systems - это консольное приложение на Python, которое использует консольную утилиту tracert и библиотеку IPWhois для отображения ip адресов пройденных маршрутизаторов, номера автономных систем, страны и провайдера.

Автор
-----

Меньшиков Александр Сергеевич. 2 курс. Группа КН-202.

Инструкция по запуску
---------------------

Для запуска приложения необходимо выполнить команду:

```shell
py tracer.py <ip\domain_name>
```
Где `ip\domain name` - это ip адрес или доменное имя, для которого требуется определить маршрут следования.

Используемые технологии
-----------------------

Tracer of Autonomous Systems написан на языке программирования Python. Для реализации была использована консольная утилита tracert и библиотека IPWhois.

Результаты работы
-----------------

После выполнения программы выводится таблица с ip адресами пройденных маршрутизаторов, номером автономной системы, страной и провайдером, если эти данные доступны.

Пример запуска:

```shell
py tracer.py 8.8.8.8
```

Пример вывода:

```
Tracing a route to "8.8.8.8":  

+----+----------------+-------+---------+-----------------+ 
| #  |       ip       |  asn  | country |     provider    | 
+----+----------------+-------+---------+-----------------+ 
| 1  |  192.168.3.1   |   -   |    -    |        -        | 
| 2  | 10.242.255.255 |   -   |    -    |        -        | 
| 3  |  10.7.32.185   |   -   |    -    |        -        | 
| 4  |  10.7.32.170   |   -   |    -    |        -        | 
| 5  |  91.221.180.4  | 13094 |    RU   |      SFO-IX     | 
| 6  | 108.170.250.51 | 15169 |    US   |      GOOGLE     | 
| 7  | 142.251.49.158 | 15169 |    US   |      GOOGLE     | 
| 8  | 216.239.57.222 | 15169 |    US   |      GOOGLE     |
| 9  | 216.239.62.15  | 15169 |    US   |      GOOGLE     | 
| 10 |    8.8.8.8     | 15169 |    US   | LVLT-GOGL-8-8-8 | 
+----+----------------+-------+---------+-----------------+  

Tracing completed.
```
