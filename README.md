Для запуска приложения необходимо поменять в application.yml параметры базы данных.
Схема создастся сама из schema.sql

Документация доступна по ссылке http://localhost:8080/swagger-ui/index.html# после запуска приложения.
Определено 4 эндпоинта: register, login, refresh, logout. Название полностью отражает что они делают.

Реализация jwt использует AES шифрование и ECDSA подпись, однако этими параметрами легко управлять через application.yml файл.
