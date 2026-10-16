using System;
using System.Globalization;
using System.Windows.Data;

namespace ReverseToolkit.Localization
{
    public class LocalizationConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // parameter обычно содержит ключ локализации; если его нет — возвращаем value (текущее значение привязки)
            if (parameter is string key)
            {
                return LocalizationManager.Instance[key];
            }

            // Ранее возвращался parameter — это неправильно. Возвращаем value, чтобы привязка работала корректно.
            return value ?? string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
