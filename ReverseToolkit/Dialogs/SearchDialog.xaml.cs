using System.Windows;
using ReverseToolkit.Localization;

namespace ReverseToolkit
{
    public partial class SearchDialog : Window
    {
        public string SearchPattern { get; private set; } = string.Empty;
        private LocalizationManager _loc;

        public SearchDialog()
        {
            InitializeComponent();
            _loc = LocalizationManager.Instance;
            Title = _loc["Dialog.Search"];
            PromptTextBlock.Text = _loc["Dialog.EnterSearchPattern"];
            SearchButton.Content = _loc["Button.Search"];
            CancelButton.Content = _loc["Button.Cancel"];
        }

        private void Search_Click(object sender, RoutedEventArgs e)
        {
            SearchPattern = SearchPatternTextBox.Text;
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
