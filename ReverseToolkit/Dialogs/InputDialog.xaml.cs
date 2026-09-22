using System.Windows;
using ReverseToolkit.Localization;

namespace ReverseToolkit
{
    public partial class InputDialog : Window
    {
        public string InputValue { get; private set; } = string.Empty;
        private LocalizationManager _loc;

        public InputDialog(string prompt)
        {
            InitializeComponent();
            _loc = LocalizationManager.Instance;
            PromptTextBlock.Text = prompt;
            Title = _loc["Dialog.EnterValue"];
            OKButton.Content = _loc["Button.OK"];
            CancelButton.Content = _loc["Button.Cancel"];
        }

        private void OK_Click(object sender, RoutedEventArgs e)
        {
            InputValue = InputTextBox.Text;
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
