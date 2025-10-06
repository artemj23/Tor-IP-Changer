# Tor IP Changer

---
## English

### Project Description
Tor IP Changer is a comprehensive Windows desktop application designed for users who prioritize privacy and anonymity online. Developed using Python and the modern `customtkinter` framework, it offers an intuitive graphical interface for controlling the Tor network directly from your desktop. The core purpose of this tool is to simplify the process of routing your internet traffic through Tor, allowing you to change your public-facing IP address with a single click. It bundles a local Tor client, making it a self-contained solution.

### Key Features
*   **One-Click IP Change:** Instantly request a new IP address by signaling the Tor network for a new identity.
*   **System-Wide Proxy:** Route all your PC's internet traffic through Tor by enabling the system proxy setting.
*   **Exit Node Selection:** Choose a specific country for your exit node to make your traffic appear from that location.
*   **Bridge Support:** Includes a built-in scanner to find and use Tor bridges, helping to bypass network censorship.
*   **Connection Monitoring:** Automatically checks the Tor connection and can re-establish a new circuit if it drops.

### How to Use
1.  **Start the Application:** Launch the `tor_ip_changer.exe` file. The application will automatically start the Tor process in the background.
2.  **Wait for Connection:** The application will show "Текущий IP: Получение..." (Current IP: Fetching...). Wait until it displays your new IP address. This confirms you are connected to the Tor network.
3.  **Change IP:** Click the "Сменить IP (NEWNYM)" (Change IP (NEWNYM)) button to get a new IP address.
4.  **Enable System Proxy:** To route all your computer's traffic through Tor, turn on the "Сделать системным прокси (для всего ПК)" (Set as system proxy (for entire PC)) switch.
5.  **Select Exit Country:** Choose a country from the dropdown menu under "Страна выходного узла:" (Exit node country) and click "Перезапустить Tor с текущими настройками" (Restart Tor with current settings) to apply the change.
6.  **Use Bridges:** If you are on a restricted network, check "Использовать мосты" (Use bridges). You can paste your own bridge lines or click "Найти мосты" (Find bridges) to automatically scan for working ones. After adding bridges, restart Tor.

---
## Русский

### Описание проекта
Tor IP Changer — это полнофункциональное десктопное приложение для Windows, созданное для пользователей, которые ценят конфиденциальность и анонимность в сети. Разработанное на Python с использованием современного фреймворка `customtkinter`, оно предоставляет интуитивно понятный графический интерфейс для управления сетью Tor прямо с рабочего стола. Основная цель этого инструмента — упростить процесс маршрутизации вашего интернет-трафика через Tor, позволяя сменить публичный IP-адрес в один клик. Приложение включает в себя локальный клиент Tor, что делает его автономным решением.

### Ключевые особенности
*   **Смена IP в один клик:** Мгновенно запрашивайте новый IP-адрес, отправляя сигнал сети Tor на смену личности.
*   **Системный прокси:** Направляйте весь интернет-трафик вашего ПК через Tor, включив настройку системного прокси.
*   **Выбор страны выхода:** Выберите конкретную страну для вашего выходного узла, чтобы ваш трафик выглядел исходящим из этой локации.
*   **Поддержка мостов:** Включает встроенный сканер для поиска и использования мостов Tor, что помогает обходить сетевую цензуру.
*   **Мониторинг соединения:** Автоматически проверяет соединение с Tor и может восстанавливать его, создавая новую цепочку, если оно прерывается.

### Инструкция по использованию
1.  **Запустите приложение:** Откройте файл `tor_ip_changer.exe`. Приложение автоматически запустит процесс Tor в фоновом режиме.
2.  **Дождитесь подключения:** В приложении будет отображаться "Текущий IP: Получение...". Подождите, пока не отобразится ваш новый IP-адрес. Это подтверждает, что вы подключены к сети Tor.
3.  **Сменить IP:** Нажмите кнопку "Сменить IP (NEWNYM)", чтобы получить новый IP-адрес.
4.  **Включить системный прокси:** Чтобы направить весь трафик вашего компьютера через Tor, активируйте переключатель "Сделать системным прокси (для всего ПК)".
5.  **Выбрать страну выхода:** Выберите страну из выпадающего меню "Страна выходного узла:" и нажмите "Перезапустить Tor с текущими настройками", чтобы применить изменение.
6.  **Использовать мосты:** Если вы находитесь в сети с ограничениями, установите флажок "Использовать мосты". Вы можете вставить свои собственные строки мостов или нажать "Найти мосты", чтобы автоматически найти рабочие. После добавления мостов перезапустите Tor.