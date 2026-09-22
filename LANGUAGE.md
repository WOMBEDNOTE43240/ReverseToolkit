# 🌍 Multi-Language Support / Поддержка нескольких языков

## English

### Supported Languages
- **English** (en) - Default
- **Russian** (ru)

### How to Switch Language

**Method 1: Using Menu**
1. Open the application
2. Click on menu: `Tools` → `Language`
3. The entire interface switches instantly!

**Method 2: Programmatically**
The language switches automatically between English and Russian each time you click the Language menu item.

### What Gets Translated

✅ **Complete interface localization:**
- All menu items
- All button labels
- All tab names
- All dialog windows
- All status messages
- All error messages
- All table headers
- All tooltips

### Language Persistence

Currently, the language setting is **not persisted** between sessions. The application always starts in English.

To add persistence, you can:
1. Save the language preference to a settings file
2. Load it on application startup

---

## Русский

### Поддерживаемые языки
- **Английский** (en) - По умолчанию
- **Русский** (ru)

### Как переключить язык

**Способ 1: Через меню**
1. Откройте приложение
2. Нажмите на меню: `Tools` → `Language` (или `Инструменты` → `Язык`)
3. Весь интерфейс переключится мгновенно!

**Способ 2: Программно**
Язык автоматически переключается между английским и русским каждый раз при нажатии на пункт меню Language.

### Что переводится

✅ **Полная локализация интерфейса:**
- Все пункты меню
- Все надписи на кнопках
- Все названия вкладок
- Все диалоговые окна
- Все статусные сообщения
- Все сообщения об ошибках
- Все заголовки таблиц
- Все подсказки

### Сохранение языка

В данный момент настройка языка **не сохраняется** между сессиями. Приложение всегда запускается на английском языке.

Чтобы добавить сохранение настроек:
1. Сохраняйте предпочтение языка в файл настроек
2. Загружайте его при запуске приложения

---

## For Developers / Для разработчиков

### Architecture

The localization system consists of:

1. **LocalizationManager.cs** - Main localization manager
   - Singleton pattern
   - Dictionary-based translation storage
   - Property change notification for UI updates
   - Supports adding new languages easily

2. **LocalizationConverter.cs** - XAML value converter
   - Converts localization keys to translated strings
   - Used in XAML bindings

3. **XAML Bindings** - UI elements use bindings
   ```xaml
   <Button Content="{Binding [Button.Open]}"/>
   ```

4. **Code-behind** - Uses LocalizationManager instance
   ```csharp
   private LocalizationManager _loc = LocalizationManager.Instance;
   MessageBox.Show(_loc["Error.Title"]);
   ```

### Adding a New Language

1. Open `LocalizationManager.cs`
2. Add new dictionary in `LoadTranslations()`:
   ```csharp
   _translations["de"] = new Dictionary<string, string>
   {
       ["Menu.File"] = "Datei",
       ["Menu.Open"] = "Öffnen",
       // ... add all translations
   };
   ```

3. Update `ChangeLanguage_Click` to include new language:
   ```csharp
   // Cycle through languages: en → ru → de → en
   _loc.CurrentLanguage = _loc.CurrentLanguage == "en" ? "ru" 
                        : _loc.CurrentLanguage == "ru" ? "de" 
                        : "en";
   ```

### Adding New Translation Keys

1. Add key to **both** English and Russian dictionaries in `LocalizationManager.cs`:
   ```csharp
   // English
   ["YourNewKey"] = "Your English Text",
   
   // Russian
   ["YourNewKey"] = "Ваш русский текст",
   ```

2. Use in XAML:
   ```xaml
   <TextBlock Text="{Binding [YourNewKey]}"/>
   ```

3. Or use in C#:
   ```csharp
   string text = _loc["YourNewKey"];
   ```

### Translation Key Naming Convention

Keys follow this pattern:
- `Menu.*` - Menu items
- `Button.*` - Button labels
- `Tab.*` - Tab names
- `Status.*` - Status bar messages
- `Error.*` - Error messages
- `Success.*` - Success messages
- `Info.*` - Information messages
- `Dialog.*` - Dialog-related text
- `PE.*` - PE Analyzer specific
- `Memory.*` - Memory Scanner specific
- `Pattern.*` - Pattern Scanner specific
- `Network.*` - Network Monitor specific
- `Hex.*` - Hex Editor specific
- `Disasm.*` - Disassembler specific

### String Formatting

For strings with placeholders, use `string.Format`:

```csharp
// In LocalizationManager
["Status.FileSelected"] = "File selected: {0}",

// In code
UpdateStatus(string.Format(_loc["Status.FileSelected"], fileName));
```

### Best Practices

1. ✅ Always add translations to **all** language dictionaries
2. ✅ Use meaningful key names
3. ✅ Keep translations consistent in style and tone
4. ✅ Test language switching after adding new strings
5. ❌ Don't hardcode strings in XAML or C#
6. ❌ Don't forget to bind DataContext in XAML

---

## Testing / Тестирование

### Test Checklist

- [ ] Switch language using menu
- [ ] Verify all UI elements update
- [ ] Check dialog windows
- [ ] Test error messages
- [ ] Test status bar messages
- [ ] Verify table headers
- [ ] Check tooltips
- [ ] Test all tabs
- [ ] Test all buttons

### Known Issues

None currently. If you find any untranslated strings, please report them!

---

## Future Improvements / Будущие улучшения

### Planned Features

1. **Language Persistence**
   - Save selected language to config file
   - Auto-load on startup

2. **More Languages**
   - German
   - French
   - Spanish
   - Chinese

3. **Regional Settings**
   - Date/time formats
   - Number formats
   - Currency formats

4. **User Interface**
   - Language selector in settings
   - Flag icons for languages
   - Dropdown menu with all languages

---

**Happy translating! / Приятного перевода!** 🌍
