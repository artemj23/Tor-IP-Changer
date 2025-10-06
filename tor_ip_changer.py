import customtkinter
import tkinter 
import socket
import threading
import time
import os
import binascii
import logging
import subprocess
import winreg
import configparser
import ctypes
import asyncio
import json
import sys
from bridge_scanner import BridgeScanner
from countries import FALLBACK_COUNTRIES

try:
    if getattr(sys, 'frozen', False):
        BASE_DIR = os.path.dirname(sys.executable)
    else:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.getcwd()

class TorIpChangerApp:
    TOR_EXE_PATH = os.path.join(BASE_DIR, 'torprojekt', 'tor', 'tor.exe')
    TOR_DATA_DIR = os.path.join(BASE_DIR, 'tor_data')
    GEOIP_FILE = os.path.join(BASE_DIR, 'torprojekt', 'data', 'geoip')
    GEOIPV6_FILE = os.path.join(BASE_DIR, 'torprojekt', 'data', 'geoip6')
    COUNTRIES_INI = os.path.join(BASE_DIR, 'countries.ini')
    SETTINGS_INI = os.path.join(BASE_DIR, 'settings.ini')
    LOG_FILE = os.path.join(BASE_DIR, 'tor_ip_changer.log')
    CRASH_LOG_FILE = os.path.join(BASE_DIR, 'tor_ip_changer_crash.log')
    MAIN_CRASH_LOG_FILE = os.path.join(BASE_DIR, 'tor_ip_changer_main_crash.log')

    CONTROL_PORT = 9151
    SOCKS_PORT = 9150
    
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37

    def __init__(self, root):
        try:
            self.tor_process = None
            self.root = root
            self.stop_event = threading.Event()

            customtkinter.set_appearance_mode("System")
            customtkinter.set_default_color_theme("blue")

            self.setup_logging()

            if not self.check_required_files():
                return

            self.setup_gui()
            self.load_countries()
            self.load_settings()

            self.start_tor_process()
            self.log("Tor IP Changer готов к работе.")


            self.health_check_thread = threading.Thread(target=self._health_check_worker, daemon=True)
            self.health_check_thread.start()

        except Exception as e:
            self.log(f"Критическая ошибка при инициализации: {e}", level=logging.CRITICAL)
            if root:
                root.destroy()

    def check_required_files(self):
        """Checks if all required files and folders exist next to the executable."""
        required_paths = [
            self.TOR_EXE_PATH,
            os.path.join(BASE_DIR, 'torprojekt'),
            self.GEOIP_FILE,
            self.GEOIPV6_FILE,
        ]
        missing_files = []
        for path in required_paths:
            if not os.path.exists(path):
                missing_files.append(os.path.basename(path))
        
        if missing_files:
            error_message = f"Критическая ошибка: Отсутствуют необходимые файлы/папки: {', '.join(missing_files)}. Убедитесь, что они находятся в той же папке, что и .exe файл."
            self.log(error_message, level=logging.CRITICAL)
            
            try:
                import tkinter as tk
                from tkinter import messagebox
                temp_root = tk.Tk()
                temp_root.withdraw()
                messagebox.showerror("Критическая ошибка", error_message)
            except Exception as e:
                self.log(f"Не удалось показать диалоговое окно с ошибкой: {e}", level=logging.ERROR)

            if self.root:
                self.root.destroy()
            return False
        return True

    def setup_gui(self):
        self.root.title("Tor IP Changer")

        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, 'myicon.ico')
            else:
                icon_path = os.path.join(BASE_DIR, 'myicon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
                if os.name == 'nt':
                    myappid = 'mycompany.toripchanger.1' 
                    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
            else:
                self.log("Файл иконки 'myicon.ico' не найден.", level=logging.WARNING)
        except Exception as e:
            self.log(f"Не удалось загрузить иконку: {e}", level=logging.WARNING)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.resizable(False, False)
        self.root.grid_columnconfigure(0, weight=1)

        self.ip_label = customtkinter.CTkLabel(self.root, text="Текущий IP: Получение...")
        self.ip_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.change_ip_button = customtkinter.CTkButton(self.root, text="Сменить IP (NEWNYM)", command=self.schedule_ip_change)
        self.change_ip_button.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        settings_frame = customtkinter.CTkFrame(self.root)
        settings_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        settings_frame.grid_columnconfigure(0, weight=1)

        self.system_proxy_var = tkinter.BooleanVar()
        self.system_proxy_check = customtkinter.CTkSwitch(settings_frame, text="Сделать системным прокси (для всего ПК)", variable=self.system_proxy_var, command=self.toggle_system_proxy)
        self.system_proxy_check.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.auto_change_var = tkinter.BooleanVar()
        self.auto_change_check = customtkinter.CTkSwitch(settings_frame, text="Автоматически менять IP при потере соединения", variable=self.auto_change_var)
        self.auto_change_check.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        country_frame = customtkinter.CTkFrame(self.root)
        country_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        country_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(country_frame, text="Страна выходного узла:").grid(row=0, column=0, padx=10, pady=(5,0), sticky="w")
        self.countries = {"Любая": "any"}
        self.country_var = tkinter.StringVar()
        self.country_combo = customtkinter.CTkComboBox(country_frame, variable=self.country_var, state='readonly')
        self.country_combo.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        bridge_frame = customtkinter.CTkFrame(self.root)
        bridge_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")
        bridge_frame.grid_columnconfigure(0, weight=1)

        self.use_bridges_var = tkinter.BooleanVar()
        customtkinter.CTkCheckBox(bridge_frame, text="Использовать мосты", variable=self.use_bridges_var).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        customtkinter.CTkLabel(bridge_frame, text="Список мостов (один на строку):").grid(row=1, column=0, padx=10, pady=(5,0), sticky="w")
        self.bridges_text = customtkinter.CTkTextbox(bridge_frame, height=100)
        self.bridges_text.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.scan_bridges_button = customtkinter.CTkButton(bridge_frame, text="Найти мосты", command=self.start_bridge_scan)
        self.scan_bridges_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        self.restart_button = customtkinter.CTkButton(bridge_frame, text="Перезапустить Tor с текущими настройками", command=self.restart_tor_with_new_config)
        self.restart_button.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

        proxy_info_frame = customtkinter.CTkFrame(self.root, fg_color="transparent")
        proxy_info_frame.grid(row=5, column=0, padx=10, pady=(0, 5), sticky="ew")
        customtkinter.CTkLabel(proxy_info_frame, text="Локальный SOCKS5 прокси:").pack(side="left", padx=(10, 0))
        proxy_address_text = f"127.0.0.1:{self.SOCKS_PORT}"
        self.proxy_address_label = customtkinter.CTkLabel(proxy_info_frame, text=proxy_address_text, font=customtkinter.CTkFont(weight="bold"), cursor="hand2")
        self.proxy_address_label.pack(side="left", padx=5)
        self.proxy_address_label.bind("<Button-1>", lambda e: self._copy_to_clipboard(proxy_address_text, "Адрес прокси"))

        self.log_area = customtkinter.CTkTextbox(self.root, height=120, state="disabled")
        self.log_area.grid(row=6, column=0, padx=10, pady=(5, 10), sticky="ew")

    def load_settings(self):
        try:
            config = configparser.ConfigParser()
            if not os.path.exists(self.SETTINGS_INI):
                self.log("Файл настроек не найден. Создание файла с настройками по умолчанию.", level=logging.WARNING)
                self._save_settings() # Save default settings
                # After saving, we can just return as the UI will have default values
                return

            config.read(self.SETTINGS_INI, encoding='utf-8')
            
            if 'Settings' in config:
                settings = config['Settings']
                self.country_var.set(settings.get('exitnode', 'Любая'))
                self.use_bridges_var.set(settings.getboolean('usebridges', False))
                self.auto_change_var.set(settings.getboolean('autochangewhenoffline', False))
                
                bridges_base64 = settings.get('bridges', '')
                if bridges_base64:
                    bridges_decoded = binascii.a2b_base64(bridges_base64.encode()).decode('utf-8')
                    self.bridges_text.insert('1.0', bridges_decoded)
                
                self.log("Настройки успешно загружены.")
        except Exception as e:
            self.log(f"Ошибка загрузки настроек: {e}", level=logging.ERROR)

    def _save_settings(self):
        try:
            config = configparser.ConfigParser()
            config['Settings'] = {
                'exitnode': self.country_var.get(),
                'usebridges': str(self.use_bridges_var.get()),
                'autochangewhenoffline': str(self.auto_change_var.get()),
                'systemproxyenabled': str(self.system_proxy_var.get())
            }

            bridges_text = self.bridges_text.get('1.0', "end-1c")
            bridges_base64 = binascii.b2a_base64(bridges_text.encode('utf-8')).decode().strip()
            config['Settings']['bridges'] = bridges_base64

            with open(self.SETTINGS_INI, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            self.log("Все настройки сохранены в settings.ini.")
        except Exception as e:
            self.log(f"Ошибка сохранения настроек: {e}", level=logging.ERROR)

    def load_countries(self):
        config = configparser.ConfigParser()
        self.countries.update(FALLBACK_COUNTRIES)
        
        try:
            if not os.path.exists(self.COUNTRIES_INI):
                self.log(f"'{self.COUNTRIES_INI}' не найден. Создание...")
                self._save_countries_to_ini(FALLBACK_COUNTRIES)
            else:
                config.read(self.COUNTRIES_INI, encoding='utf-8')
                countries_from_ini = dict(config.items('Countries'))
                self.countries.update(countries_from_ini)
        except Exception as e:
            self.log(f"Ошибка загрузки '{self.COUNTRIES_INI}': {e}. Используется базовый список.", level=logging.WARNING)
        finally:
            self.country_combo.configure(values=list(self.countries.keys()))
            self.country_combo.set("Любая")
            self.log(f"Загружено {len(self.countries)-1} стран.")

    def _save_countries_to_ini(self, country_dict):
        try:
            config = configparser.ConfigParser()
            config['Countries'] = country_dict
            with open(self.COUNTRIES_INI, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            self.log(f"Файл '{self.COUNTRIES_INI}' успешно создан/обновлен.")
        except Exception as e:
            self.log(f"Ошибка сохранения '{self.COUNTRIES_INI}': {e}", level=logging.ERROR)

    def on_closing(self):
        try:
            self.log("Сохранение настроек и завершение работы...")
            self._save_settings()
        except Exception as e:
            self.log(f"Ошибка при сохранении настроек: {e}", level=logging.ERROR)
        finally:
            self.stop_event.set()
            if self.system_proxy_var.get():
                self.log("Отключение системного прокси...")
                self.set_system_proxy(enable=False)

            self.log("Остановка процесса Tor...")
            if self.tor_process and self.tor_process.poll() is None:
                try:
                    self.tor_process.terminate()
                    self.tor_process.wait(timeout=5)
                    self.log("Процесс Tor штатно остановлен.")
                except subprocess.TimeoutExpired:
                    self.log("Процесс Tor не ответил, принудительное завершение.", level=logging.WARNING)
                    self.tor_process.kill()
                    self.tor_process.wait()
                except Exception as e:
                    self.log(f"Ошибка при остановке Tor: {e}", level=logging.ERROR)

            if hasattr(self, 'health_check_thread') and self.health_check_thread.is_alive():
                self.health_check_thread.join(timeout=1)

            if self.root and self.root.winfo_exists():
                self.root.destroy()

    def start_tor_process(self):
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE

            command = [
                self.TOR_EXE_PATH,
                '--ControlPort', str(self.CONTROL_PORT),
                '--SOCKSPort', str(self.SOCKS_PORT),
                '--CookieAuthentication', '1',
                '--DataDirectory', self.TOR_DATA_DIR,
                '--GeoIPFile', self.GEOIP_FILE,
                '--GeoIPv6File', self.GEOIPV6_FILE
            ]

            selected_country_name = self.country_var.get()
            country_code = self.countries.get(selected_country_name)

            if country_code and country_code != "any":
                self.log(f"Установка страны выходного узла: {selected_country_name} ({country_code.upper()})")
                command.extend(['ExitNodes', f'{{{country_code}}}'])

            use_bridges = self.use_bridges_var.get()
            bridges = self.bridges_text.get('1.0', 'end-1c').strip()

            if use_bridges and bridges:
                self.log("Включение мостов...")
                command.extend(['--UseBridges', '1'])
                for bridge_line in bridges.split('\n'):
                    if bridge_line.strip():
                        command.extend(['Bridge', bridge_line.strip()])
            else:
                self.log("Запуск Tor в обычном режиме (без мостов).")

            self.tor_process = subprocess.Popen(
                command,
                startupinfo=si,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            threading.Thread(target=self._read_tor_output, args=(self.tor_process.stdout,), daemon=True).start()
            threading.Thread(target=self._read_tor_output, args=(self.tor_process.stderr,), daemon=True).start()

            self.log("Процесс Tor запущен.")
        except FileNotFoundError:
            self.log(f"Критическая ошибка: {self.TOR_EXE_PATH} не найден.", level=logging.CRITICAL)
        except Exception as e:
            self.log(f"Критическая ошибка при запуске Tor: {e}", level=logging.CRITICAL)

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.LOG_FILE, 'w', 'utf-8'),
            ]
        )

    def log(self, message, level=logging.INFO):
        try:
            logging.log(level, message)

            log_message = f"{message}\n"
            if hasattr(self, 'log_area') and self.log_area:
                self.log_area.configure(state="normal")
                self.log_area.insert("end", log_message)
                self.log_area.see("end")
                self.log_area.configure(state="disabled")
        except Exception as e:
            print(f"Ошибка логирования: {e}\nСообщение: {message}")

    def get_current_ip(self):
        self.log("Получение публичного IP-адреса...")
        urls = [
            "https://ipv4.icanhazip.com/",
            "https://ident.me/"
        ]

        for url in urls:
            try:
                self.log(f"Проверка IP через")
                command = [
                    'curl',
                    '--silent',
                    '--socks5-hostname', f'127.0.0.1:{self.SOCKS_PORT}',
                    '--connect-timeout', '15',
                    '-L',
                    url
                ]
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                
                result = subprocess.run(
                    command, 
                    capture_output=True, 
                    text=True, 
                    check=True, 
                    startupinfo=si,
                    encoding='utf-8',
                    errors='ignore'
                )
                ip = result.stdout.strip()
                if ip and ip.count('.') == 3 and all(p.isdigit() for p in ip.split('.')):
                    self.log(f"Получен IP: {ip}")
                    return ip
                else:
                    self.log(f"Получен невалидный ответ от {url}: {ip}", level=logging.WARNING)
            except subprocess.CalledProcessError as e:
                self.log(f"Ошибка curl при получении IP с {url}: {e.stderr}", level=logging.WARNING)
                continue
            except FileNotFoundError:
                self.log(f"Ошибка: команда 'curl' не найдена. Установите curl или добавьте его в PATH.", level=logging.CRITICAL)
                return "Ошибка (curl)"
            except Exception as e:
                self.log(f"Неизвестная ошибка при получении IP с {url}: {e}", level=logging.ERROR)
                continue

        self.log("Не удалось получить IP ни с одного из сервисов.", level=logging.ERROR)
        return "Ошибка (все сервисы)"

    def update_ip_display(self):
        self.change_ip_button.configure(state="disabled")
        self.ip_label.configure(text="Текущий IP: Получение...")
        threading.Thread(target=self._update_ip_worker, daemon=True).start()

    def _update_ip_worker(self):
        new_ip = self.get_current_ip()
        self.root.after(0, self._update_ip_ui, new_ip)

    def _update_ip_ui(self, new_ip):
        self.ip_label.configure(text=f"Текущий IP: {new_ip}")
        if "Ошибка" not in new_ip:
            self.log("IP-адрес успешно обновлен.")
        self.change_ip_button.configure(state="normal")

    def change_tor_ip(self):
        try:
            cookie_path = os.path.join(self.TOR_DATA_DIR, 'control_auth_cookie')
            for i in range(10): 
                if os.path.exists(cookie_path) and os.path.getsize(cookie_path) > 0:
                    break
                time.sleep(1)
            else:
                return "Ошибка: Cookie-файл аутентификации Tor не найден или пуст. Tor может все еще запускаться."

            with open(cookie_path, 'rb') as f:
                cookie = f.read()
            hex_cookie = binascii.hexlify(cookie).decode('utf-8')

            with socket.create_connection(('127.0.0.1', self.CONTROL_PORT), timeout=10) as s:
                auth_command = f'AUTHENTICATE {hex_cookie}\r\n'.encode('utf-8')
                s.sendall(auth_command)
                response = s.recv(1024)
                if not response.startswith(b'250'):
                    return f"Ошибка аутентификации Tor: {response.decode(errors='ignore').strip()}"

                s.sendall(b'SIGNAL NEWNYM\r\n')
                response = s.recv(1024)
                if response.startswith(b'250'):
                    return "Сигнал NEWNYM успешно отправлен."
                else:
                    return f"Ошибка сигнала NEWNYM: {response.decode(errors='ignore').strip()}"
        except FileNotFoundError:
             return f"Ошибка: Cookie-файл не найден по пути {cookie_path}."
        except ConnectionRefusedError:
            return f"Ошибка подключения: порт управления Tor ({self.CONTROL_PORT}) недоступен. Tor запущен?"
        except socket.timeout:
            return "Ошибка: Превышен тайм-аут подключения к порту управления Tor."
        except Exception as e:
            return f"Неизвестная ошибка при смене IP: {e}"

    def schedule_ip_change(self):
        self.change_ip_button.configure(state="disabled")
        self.log("Отправка сигнала NEWNYM в Tor...")
        threading.Thread(target=self._change_ip_worker, daemon=True).start()

    def _change_ip_worker(self):
        self.root.after(0, self.log, "Получение текущего IP перед сменой...")
        old_ip = self.get_current_ip()
        if "Ошибка" in old_ip:
            self.root.after(0, self.log, f"Не удалось получить текущий IP ({old_ip}). Смена IP отменена.", logging.ERROR)
            self.root.after(0, lambda: self.change_ip_button.configure(state="normal"))
            return

        result = self.change_tor_ip()
        is_error = "Ошибка" in result
        self.root.after(0, self.log, result, logging.ERROR if is_error else logging.INFO)

        if is_error:
            self.root.after(0, lambda: self.change_ip_button.configure(state="normal"))
            return

        self.root.after(0, self.log, "Ожидание смены IP-адреса (до 60 секунд)...")
        success = False
        new_ip = old_ip
        for i in range(12): 
            time.sleep(5)
            new_ip = self.get_current_ip()
            if "Ошибка" not in new_ip and new_ip != old_ip:
                self.root.after(0, self.log, f"IP-адрес успешно изменен с {old_ip} на {new_ip}.")
                success = True
                break
            else:
                self.root.after(0, self.log, f"Попытка {i + 1}/12: IP еще не изменился.")

        if not success:
            self.root.after(0, self.log, "Не удалось подтвердить смену IP в течение 60 секунд.", logging.WARNING)

        self.root.after(0, self._update_ip_ui, new_ip)

    def toggle_system_proxy(self):
        try:
            if self.system_proxy_var.get():
                self.log("Включение системного прокси...")
                self.set_system_proxy(enable=True, proxy_server=f'socks=127.0.0.1:{self.SOCKS_PORT}')
            else:
                self.log("Отключение системного прокси...")
                self.set_system_proxy(enable=False)
        except Exception as e:
            self.log(f"Ошибка переключения системного прокси: {e}", level=logging.ERROR)

    def set_system_proxy(self, enable=False, proxy_server=""):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as internet_settings:
                if enable:
                    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
                    self.log(f"Системный прокси ВКЛЮЧЕН ({proxy_server}).")
                else:
                    winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, "")
                    self.log("Системный прокси ВЫКЛЮЧЕН.")

            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(None, self.INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            internet_set_option(None, self.INTERNET_OPTION_REFRESH, None, 0)

        except PermissionError:
            self.log("Ошибка доступа: Не удалось изменить настройки прокси. Попробуйте запустить от имени администратора.", level=logging.ERROR)
            if self.system_proxy_var.get() != enable:
                 self.system_proxy_var.set(not enable) 
        except FileNotFoundError:
            self.log(f"Ошибка: Не найден ключ реестра '{key_path}'.", level=logging.ERROR)
            if self.system_proxy_var.get() != enable:
                 self.system_proxy_var.set(not enable)
        except Exception as e:
            self.log(f"Неизвестная ошибка изменения настроек прокси: {e}", level=logging.ERROR)
            if self.system_proxy_var.get() != enable:
                 self.system_proxy_var.set(not enable)

    def restart_tor_with_new_config(self):
        self.log("Перезапуск Tor с новой конфигурацией...")
        self.restart_button.configure(state="disabled")
        self.change_ip_button.configure(state="disabled")
        threading.Thread(target=self._restart_worker, daemon=True).start()

    def _restart_worker(self):
        try:
            if self.tor_process and self.tor_process.poll() is None:
                self.root.after(0, self.log, "Остановка текущего процесса Tor...")
                try:
                    self.tor_process.terminate()
                    self.tor_process.wait(timeout=5)
                    self.root.after(0, self.log, "Процесс Tor штатно остановлен.")
                except subprocess.TimeoutExpired:
                    self.root.after(0, self.log, "Процесс Tor не ответил, принудительное завершение.", logging.WARNING)
                    self.tor_process.kill()
                    self.tor_process.wait() 
                    self.root.after(0, self.log, "Процесс Tor принудительно остановлен.", logging.WARNING)
                except Exception as e:
                    self.root.after(0, self.log, f"Ошибка при остановке Tor: {e}", logging.ERROR)

            time.sleep(1) 

            self.root.after(0, self.log, "Запуск нового процесса Tor...")
            self.start_tor_process()
        except Exception as e:
            self.log(f"Ошибка в потоке перезапуска Tor: {e}", level=logging.ERROR)
        finally:
            self.root.after(0, lambda: self.restart_button.configure(state="normal"))
            self.root.after(0, lambda: self.change_ip_button.configure(state="normal"))

    def check_tor_connection(self):
        self.log("Проверка связи через Tor...")
        try:
            command = [
                'curl',
                '--silent',
                '--socks5-hostname', f'127.0.0.1:{self.SOCKS_PORT}',
                '--connect-timeout', '10',
                '-L',
                "https://check.torproject.org/api/ip"
            ]
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=True, 
                startupinfo=si,
                encoding='utf-8',
                errors='ignore'
            )
            data = json.loads(result.stdout)
            if data.get("IsTor"):
                self.log(f"Связь через Tor в норме. IP: {data.get('IP')}")
                return True
            else:
                self.log("Проверка связи показала, что трафик идет не через Tor.", level=logging.WARNING)
                return False
        except FileNotFoundError:
            self.log(f"Ошибка: команда 'curl' не найдена. Установите curl или добавьте его в PATH.", level=logging.CRITICAL)
            return False
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.log(f"Ошибка проверки связи: {e}", level=logging.WARNING)
            return False
        except Exception as e:
            self.log(f"Неизвестная ошибка при проверке связи: {e}", level=logging.ERROR)
            return False

    def _health_check_worker(self):
        if self.stop_event.wait(20):
            return

        while not self.stop_event.is_set():
            try:
                if self.auto_change_var.get():
                    if not self.check_tor_connection():
                        self.log("Потеряна связь. Инициирую смену IP...", level=logging.WARNING)
                        if self.change_ip_button.cget("state") == "normal":
                            self.root.after(0, self.schedule_ip_change)
            except Exception as e:
                self.log(f"Критическая ошибка в цикле проверки соединения: {e}", level=logging.ERROR)

            if self.stop_event.wait(60):
                break

    def _read_tor_output(self, pipe):
        try:
            for line in iter(pipe.readline, ''):
                if self.stop_event.is_set():
                    break
                line_stripped = line.strip()
                if line_stripped:
                    self.root.after(0, self.log, f"[Tor] {line_stripped}")
                if "Bootstrapped 100% (done): Done" in line_stripped:
                    self.root.after(0, self.update_ip_display)
        except Exception as e:
            if not (isinstance(e, (ValueError, OSError)) and "I/O operation on closed file" in str(e)):
                 self.root.after(0, self.log, f"Ошибка чтения вывода Tor: {e}", logging.ERROR)
        finally:
            pipe.close()

    def _copy_to_clipboard(self, text_to_copy, name):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text_to_copy)
            self.log(f"{name} '{text_to_copy}' скопирован в буфер обмена.")
        except Exception as e:
            self.log(f"Не удалось скопировать в буфер обмена: {e}", level=logging.WARNING)

    def start_bridge_scan(self):
        self.log("Запуск сканирования мостов...")
        self.scan_bridges_button.configure(state="disabled")
        self._bridge_scan_worker()

    def _bridge_scan_worker(self):
        def run_async_scan():
            try:
                scanner = BridgeScanner(
                    log_callback=lambda msg: self.root.after(0, self.log, msg),
                    update_bridges_callback=lambda bridges: self.root.after(0, self._append_bridges, bridges)
                )
                asyncio.run(scanner.scan())
            except Exception as e:
                self.log(f"Ошибка в потоке сканирования мостов: {e}", level=logging.ERROR)
            finally:
                self.root.after(0, lambda: self.scan_bridges_button.configure(state="normal"))
                self.log("Сканирование мостов завершено.")

        threading.Thread(target=run_async_scan, daemon=True).start()

    def _append_bridges(self, found_this_attempt):
        current_text = self.bridges_text.get("1.0", "end-1c").strip()
        new_text = "\n".join(found_this_attempt)
        if current_text:
            self.bridges_text.insert("end", "\n" + new_text)
        else:
            self.bridges_text.insert("end", new_text)


if __name__ == "__main__":
    root = None
    try:
        root = customtkinter.CTk()
        app = TorIpChangerApp(root)
        # The mainloop is only started if the app initialization was successful
        # and the root window wasn't destroyed by an early error.
        if hasattr(app, 'root') and app.root and app.root.winfo_exists():
            app.root.mainloop()
    except Exception as e:
        # This will catch errors during CTk() or TorIpChangerApp() initialization
        # before the mainloop starts.
        main_crash_log = os.path.join(os.getcwd(), 'tor_ip_changer_main_crash.log')
        logging.basicConfig(filename=main_crash_log, level=logging.CRITICAL)
        logging.critical("Критическая ошибка в __main__: %s", e, exc_info=True)
        # Attempt to show a final error message if tkinter is still usable
        try:
            import tkinter as tk
            from tkinter import messagebox
            temp_root = tk.Tk()
            temp_root.withdraw()
            messagebox.showerror("Критическая ошибка", f"Произошла непредвиденная ошибка: {e}\n\nПодробности в {main_crash_log}")
        except Exception:
            pass # If tkinter fails here, there's nothing more we can do.
    finally:
        # The `on_closing` method handles the destruction of the root window during a normal exit.
        # This `finally` block can cause an error if it tries to access the already-destroyed window.
        # The main cleanup is handled by the application's `on_closing` protocol.
        pass