using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;

namespace ReverseToolkit.Localization
{
    public class LocalizationManager : INotifyPropertyChanged
    {
        private static LocalizationManager? _instance;
        private string _currentLanguage = "en";
        private Dictionary<string, Dictionary<string, string>> _translations;

        public event PropertyChangedEventHandler? PropertyChanged;

        public static LocalizationManager Instance
        {
            get
            {
                if (_instance == null)
                    _instance = new LocalizationManager();
                return _instance;
            }
        }

        private LocalizationManager()
        {
            _translations = new Dictionary<string, Dictionary<string, string>>();
            LoadTranslations();
        }

        public string CurrentLanguage
        {
            get => _currentLanguage;
            set
            {
                if (_currentLanguage != value)
                {
                    _currentLanguage = value;
                    OnPropertyChanged(nameof(CurrentLanguage));
                    OnLanguageChanged();
                }
            }
        }

        public string this[string key]
        {
            get
            {
                if (_translations.ContainsKey(_currentLanguage) && 
                    _translations[_currentLanguage].ContainsKey(key))
                {
                    return _translations[_currentLanguage][key];
                }
                return key; // Return key if translation not found
            }
        }

        private void LoadTranslations()
        {
            // English translations
            _translations["en"] = new Dictionary<string, string>
            {
                // Menu
                ["Menu.File"] = "File",
                ["Menu.OpenFile"] = "Open file",
                ["Menu.OpenProcess"] = "Open process",
                ["Menu.Exit"] = "Exit",
                ["Menu.Tools"] = "Tools",
                ["Menu.Settings"] = "Settings",
                ["Menu.About"] = "About",
                ["Menu.Language"] = "Language",
                
                // Tabs
                ["Tab.PEAnalyzer"] = "📋 PE Analyzer",
                ["Tab.HexEditor"] = "🔢 Hex Editor",
                ["Tab.MemoryScanner"] = "🧠 Memory Scanner",
                ["Tab.PatternScanner"] = "🔍 Pattern Scanner",
                ["Tab.Disassembler"] = "⚙️ Disassembler",
                ["Tab.NetworkMonitor"] = "🌐 Network Monitor",
                
                // Common buttons
                ["Button.Open"] = "Open",
                ["Button.Save"] = "Save",
                ["Button.Load"] = "Load",
                ["Button.Export"] = "Export",
                ["Button.Search"] = "Search",
                ["Button.Clear"] = "Clear",
                ["Button.Refresh"] = "Refresh",
                ["Button.Start"] = "Start",
                ["Button.Stop"] = "Stop",
                ["Button.Close"] = "Close",
                ["Button.OK"] = "OK",
                ["Button.Cancel"] = "Cancel",
                ["Button.Modify"] = "Modify",
                ["Button.Freeze"] = "Freeze",
                
                // PE Analyzer
                ["PE.LoadPE"] = "Load PE",
                ["PE.Headers"] = "Headers",
                ["PE.Sections"] = "Sections",
                ["PE.Imports"] = "Imports",
                ["PE.Exports"] = "Exports",
                ["PE.Name"] = "Name",
                ["PE.VirtualAddress"] = "Virtual Address",
                ["PE.VirtualSize"] = "Virtual Size",
                ["PE.RawSize"] = "Raw Size",
                ["PE.Characteristics"] = "Characteristics",
                ["PE.DLL"] = "DLL",
                ["PE.Function"] = "Function",
                ["PE.Address"] = "Address",
                ["PE.Ordinal"] = "Ordinal",
                ["PE.RVA"] = "RVA",
                
                // Hex Editor
                ["Hex.GoTo"] = "Go To",
                ["Hex.Offset"] = "Offset:",
                
                // Memory Scanner
                ["Memory.Processes"] = "Processes:",
                ["Memory.RefreshList"] = "Refresh list",
                ["Memory.MemorySearch"] = "Memory search:",
                ["Memory.FirstScan"] = "First Scan",
                ["Memory.NextScan"] = "Next Scan",
                ["Memory.Value"] = "Value",
                ["Memory.Previous"] = "Previous",
                ["Memory.Type"] = "Type",
                ["Memory.Actions"] = "Actions",
                
                // Pattern Scanner
                ["Pattern.Search"] = "Pattern search:",
                ["Pattern.InFile"] = "In file",
                ["Pattern.InMemory"] = "In process memory",
                ["Pattern.AddressOffset"] = "Address/Offset",
                ["Pattern.Pattern"] = "Pattern",
                ["Pattern.Context"] = "Context (bytes)",
                
                // Disassembler
                ["Disasm.Disassemble"] = "Disassemble",
                
                // Network Monitor
                ["Network.ProcessToMonitor"] = "Process to monitor:",
                ["Network.RefreshProcesses"] = "Refresh processes",
                ["Network.StartMonitoring"] = "Start monitoring",
                ["Network.ClearLog"] = "Clear log",
                ["Network.AllTraffic"] = "All traffic",
                ["Network.Time"] = "Time",
                ["Network.Protocol"] = "Protocol",
                ["Network.Source"] = "Source",
                ["Network.Destination"] = "Destination",
                ["Network.URLHost"] = "URL/Host",
                ["Network.Size"] = "Size",
                ["Network.PacketDetails"] = "Packet details:",
                
                // Status messages
                ["Status.Ready"] = "Reverse Engineering Toolkit v1.0 - Ready",
                ["Status.FileSelected"] = "File selected: {0}",
                ["Status.ProcessListOpened"] = "Process list opened",
                ["Status.PELoaded"] = "PE file successfully loaded and analyzed",
                ["Status.FileLoaded"] = "File loaded in Hex Editor",
                ["Status.ChangesSaved"] = "Changes saved",
                ["Status.ProcessListUpdated"] = "Process list updated",
                ["Status.AttachedToProcess"] = "Attached to process: {0}",
                ["Status.FirstScanComplete"] = "First scan complete. Found results: {0}",
                ["Status.NextScanComplete"] = "Next scan complete. Results: {0}",
                ["Status.MemoryModified"] = "Memory modified at address: {0:X}",
                ["Status.MemoryFrozen"] = "Memory frozen at address: {0:X}",
                ["Status.PatternSearchComplete"] = "Pattern search complete. Found: {0}",
                ["Status.SearchResultsCleared"] = "Search results cleared",
                ["Status.DisassemblyComplete"] = "Disassembly complete",
                ["Status.MonitoringStarted"] = "Monitoring started for process: {0}",
                ["Status.MonitoringStopped"] = "Monitoring stopped",
                ["Status.NetworkLogCleared"] = "Network activity log cleared",
                ["Status.AnalysisExported"] = "Analysis exported: {0}",
                ["Status.JumpToOffset"] = "Jump to offset: {0}",
                
                // Error messages
                ["Error.Title"] = "Error",
                ["Error.SelectFile"] = "Select a file for analysis",
                ["Error.LoadingPE"] = "Error loading PE file: {0}",
                ["Error.PELoadError"] = "PE load error: {0}",
                ["Error.LoadingFile"] = "Error loading file: {0}",
                ["Error.NoFileLoaded"] = "No file loaded",
                ["Error.SaveError"] = "Save error: {0}",
                ["Error.InvalidOffset"] = "Invalid offset format",
                ["Error.ScanError"] = "Scan error: {0}",
                ["Error.SelectProcess"] = "Select a process to monitor",
                ["Error.MonitoringError"] = "Monitoring start error: {0}",
                ["Error.PatternSearchError"] = "Pattern search error: {0}",
                ["Error.DisassemblyError"] = "Disassembly error: {0}",
                
                // Success messages
                ["Success.Title"] = "Success",
                ["Success.FileSaved"] = "File successfully saved!",
                ["Success.MatchesFound"] = "Found matches: {0}",
                ["Success.NoMatches"] = "No matches found",
                
                // Info messages
                ["Info.Title"] = "Information",
                ["Info.SettingsUnderDevelopment"] = "Settings under development",
                ["Info.About"] = "Reverse Engineering Toolkit v1.0\n\nComprehensive tool for reverse engineering\n\nFeatures:\n• PE Analyzer - analyze executable file structure\n• Hex Editor - view and edit binary files\n• Memory Scanner - scan process memory\n• Pattern Scanner - search byte patterns\n• Disassembler - disassemble code\n• Network Monitor - monitor network activity\n\nCreated for legitimate anti-cheat protection analysis.",
                
                // Dialog titles
                ["Dialog.EnterValue"] = "Enter value",
                ["Dialog.Search"] = "Search",
                ["Dialog.EnterSearchPattern"] = "Enter search pattern (HEX):",
                ["Dialog.EnterNewValue"] = "Enter new value:",
                ["Dialog.SearchResults"] = "Search results",
                
                // Common words
                ["Common.Ready"] = "Ready",
            };

            // Russian translations
            _translations["ru"] = new Dictionary<string, string>
            {
                // Меню
                ["Menu.File"] = "Файл",
                ["Menu.OpenFile"] = "Открыть файл",
                ["Menu.OpenProcess"] = "Открыть процесс",
                ["Menu.Exit"] = "Выход",
                ["Menu.Tools"] = "Инструменты",
                ["Menu.Settings"] = "Настройки",
                ["Menu.About"] = "О программе",
                ["Menu.Language"] = "Язык",
                
                // Вкладки
                ["Tab.PEAnalyzer"] = "📋 PE Анализатор",
                ["Tab.HexEditor"] = "🔢 Hex Редактор",
                ["Tab.MemoryScanner"] = "🧠 Сканер Памяти",
                ["Tab.PatternScanner"] = "🔍 Поиск Паттернов",
                ["Tab.Disassembler"] = "⚙️ Дизассемблер",
                ["Tab.NetworkMonitor"] = "🌐 Сетевой Монитор",
                
                // Общие кнопки
                ["Button.Open"] = "Открыть",
                ["Button.Save"] = "Сохранить",
                ["Button.Load"] = "Загрузить",
                ["Button.Export"] = "Экспорт",
                ["Button.Search"] = "Поиск",
                ["Button.Clear"] = "Очистить",
                ["Button.Refresh"] = "Обновить",
                ["Button.Start"] = "Начать",
                ["Button.Stop"] = "Остановить",
                ["Button.Close"] = "Закрыть",
                ["Button.OK"] = "OK",
                ["Button.Cancel"] = "Отмена",
                ["Button.Modify"] = "Изменить",
                ["Button.Freeze"] = "Заморозить",
                
                // PE Анализатор
                ["PE.LoadPE"] = "Загрузить PE",
                ["PE.Headers"] = "Заголовки",
                ["PE.Sections"] = "Секции",
                ["PE.Imports"] = "Импорты",
                ["PE.Exports"] = "Экспорты",
                ["PE.Name"] = "Имя",
                ["PE.VirtualAddress"] = "Виртуальный Адрес",
                ["PE.VirtualSize"] = "Виртуальный Размер",
                ["PE.RawSize"] = "Размер",
                ["PE.Characteristics"] = "Характеристики",
                ["PE.DLL"] = "DLL",
                ["PE.Function"] = "Функция",
                ["PE.Address"] = "Адрес",
                ["PE.Ordinal"] = "Порядковый",
                ["PE.RVA"] = "RVA",
                
                // Hex Редактор
                ["Hex.GoTo"] = "Перейти",
                ["Hex.Offset"] = "Смещение:",
                
                // Сканер Памяти
                ["Memory.Processes"] = "Процессы:",
                ["Memory.RefreshList"] = "Обновить список",
                ["Memory.MemorySearch"] = "Поиск в памяти:",
                ["Memory.FirstScan"] = "Первое сканирование",
                ["Memory.NextScan"] = "Следующее сканирование",
                ["Memory.Value"] = "Значение",
                ["Memory.Previous"] = "Предыдущее",
                ["Memory.Type"] = "Тип",
                ["Memory.Actions"] = "Действия",
                
                // Поиск Паттернов
                ["Pattern.Search"] = "Поиск паттерна:",
                ["Pattern.InFile"] = "В файле",
                ["Pattern.InMemory"] = "В памяти процесса",
                ["Pattern.AddressOffset"] = "Адрес/Смещение",
                ["Pattern.Pattern"] = "Паттерн",
                ["Pattern.Context"] = "Контекст (байты)",
                
                // Дизассемблер
                ["Disasm.Disassemble"] = "Дизассемблировать",
                
                // Сетевой Монитор
                ["Network.ProcessToMonitor"] = "Процесс для мониторинга:",
                ["Network.RefreshProcesses"] = "Обновить процессы",
                ["Network.StartMonitoring"] = "Начать мониторинг",
                ["Network.ClearLog"] = "Очистить лог",
                ["Network.AllTraffic"] = "Весь трафик",
                ["Network.Time"] = "Время",
                ["Network.Protocol"] = "Протокол",
                ["Network.Source"] = "Источник",
                ["Network.Destination"] = "Назначение",
                ["Network.URLHost"] = "URL/Хост",
                ["Network.Size"] = "Размер",
                ["Network.PacketDetails"] = "Детали пакета:",
                
                // Статусные сообщения
                ["Status.Ready"] = "Reverse Engineering Toolkit v1.0 - Готов к работе",
                ["Status.FileSelected"] = "Файл выбран: {0}",
                ["Status.ProcessListOpened"] = "Открыт список процессов",
                ["Status.PELoaded"] = "PE файл успешно загружен и проанализирован",
                ["Status.FileLoaded"] = "Файл загружен в Hex Editor",
                ["Status.ChangesSaved"] = "Изменения сохранены",
                ["Status.ProcessListUpdated"] = "Список процессов обновлен",
                ["Status.AttachedToProcess"] = "Подключен к процессу: {0}",
                ["Status.FirstScanComplete"] = "Первое сканирование завершено. Найдено результатов: {0}",
                ["Status.NextScanComplete"] = "Следующее сканирование завершено. Результатов: {0}",
                ["Status.MemoryModified"] = "Память изменена по адресу: {0:X}",
                ["Status.MemoryFrozen"] = "Память заморожена по адресу: {0:X}",
                ["Status.PatternSearchComplete"] = "Поиск паттерна завершен. Найдено: {0}",
                ["Status.SearchResultsCleared"] = "Результаты поиска очищены",
                ["Status.DisassemblyComplete"] = "Дизассемблирование завершено",
                ["Status.MonitoringStarted"] = "Мониторинг запущен для процесса: {0}",
                ["Status.MonitoringStopped"] = "Мониторинг остановлен",
                ["Status.NetworkLogCleared"] = "Лог сетевой активности очищен",
                ["Status.AnalysisExported"] = "Анализ экспортирован: {0}",
                ["Status.JumpToOffset"] = "Переход к offset: {0}",
                
                // Сообщения об ошибках
                ["Error.Title"] = "Ошибка",
                ["Error.SelectFile"] = "Выберите файл для анализа",
                ["Error.LoadingPE"] = "Ошибка при загрузке PE файла: {0}",
                ["Error.PELoadError"] = "Ошибка загрузки PE: {0}",
                ["Error.LoadingFile"] = "Ошибка загрузки файла: {0}",
                ["Error.NoFileLoaded"] = "Нет загруженного файла",
                ["Error.SaveError"] = "Ошибка сохранения: {0}",
                ["Error.InvalidOffset"] = "Неверный формат offset",
                ["Error.ScanError"] = "Ошибка сканирования: {0}",
                ["Error.SelectProcess"] = "Выберите процесс для мониторинга",
                ["Error.MonitoringError"] = "Ошибка запуска мониторинга: {0}",
                ["Error.PatternSearchError"] = "Ошибка поиска паттерна: {0}",
                ["Error.DisassemblyError"] = "Ошибка дизассемблирования: {0}",
                
                // Успешные сообщения
                ["Success.Title"] = "Успех",
                ["Success.FileSaved"] = "Файл успешно сохранен!",
                ["Success.MatchesFound"] = "Найдено совпадений: {0}",
                ["Success.NoMatches"] = "Совпадений не найдено",
                
                // Информационные сообщения
                ["Info.Title"] = "Информация",
                ["Info.SettingsUnderDevelopment"] = "Настройки в разработке",
                ["Info.About"] = "Reverse Engineering Toolkit v1.0\n\nКомплексный инструмент для реверс-инжиниринга\n\nВозможности:\n• PE Analyzer - анализ структуры исполняемых файлов\n• Hex Editor - просмотр и редактирование бинарных файлов\n• Memory Scanner - сканирование памяти процессов\n• Pattern Scanner - поиск байт-паттернов\n• Disassembler - дизассемблирование кода\n• Network Monitor - мониторинг сетевой активности\n\nСоздано для легитимного анализа защит от читов.",
                
                // Заголовки диалогов
                ["Dialog.EnterValue"] = "Ввод значения",
                ["Dialog.Search"] = "Поиск",
                ["Dialog.EnterSearchPattern"] = "Введите паттерн для поиска (HEX):",
                ["Dialog.EnterNewValue"] = "Введите новое значение:",
                ["Dialog.SearchResults"] = "Результаты поиска",
                
                // Общие слова
                ["Common.Ready"] = "Готов",
            };
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void OnLanguageChanged()
        {
            // Notify all properties to update
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
        }
    }
}
