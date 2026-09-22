using System;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using ReverseToolkit.Localization;

namespace ReverseToolkit
{
    public partial class MainWindow : Window
    {
        private PEAnalyzer? peAnalyzer;
        private HexEditorEngine? hexEditor;
        private MemoryScanner? memoryScanner;
        private PatternScanner? patternScanner;
        private DisassemblerEngine? disassembler;
        private NetworkMonitor? networkMonitor;
        private LocalizationManager _loc;

        public MainWindow()
        {
            InitializeComponent();
            _loc = LocalizationManager.Instance;
            InitializeModules();
            UpdateStatus(_loc["Status.Ready"]);
            
            // Subscribe to language change
            _loc.PropertyChanged += (s, e) => UpdateUIAfterLanguageChange();
        }

        private void InitializeModules()
        {
            peAnalyzer = new PEAnalyzer();
            hexEditor = new HexEditorEngine();
            memoryScanner = new MemoryScanner();
            patternScanner = new PatternScanner();
            disassembler = new DisassemblerEngine();
            networkMonitor = new NetworkMonitor();
        }

        private void UpdateStatus(string message)
        {
            StatusTextBlock.Text = $"{DateTime.Now:HH:mm:ss} - {message}";
        }

        // Menu Handlers
        private void OpenFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Executable Files (*.exe;*.dll)|*.exe;*.dll|All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                PEFilePathTextBox.Text = dialog.FileName;
                HexFilePathTextBox.Text = dialog.FileName;
                UpdateStatus(string.Format(_loc["Status.FileSelected"], dialog.FileName));
            }
        }

        private void OpenProcess_Click(object sender, RoutedEventArgs e)
        {
            MainTabControl.SelectedIndex = 2; // Memory Scanner tab
            RefreshProcesses_Click(sender, e);
            UpdateStatus(_loc["Status.ProcessListOpened"]);
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(_loc["Info.SettingsUnderDevelopment"], _loc["Info.Title"], MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(_loc["Info.About"], _loc["Menu.About"], MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ChangeLanguage_Click(object sender, RoutedEventArgs e)
        {
            // Toggle language between English and Russian
            _loc.CurrentLanguage = _loc.CurrentLanguage == "en" ? "ru" : "en";
            UpdateStatus(_loc["Status.Ready"]);
        }

        private void UpdateUIAfterLanguageChange()
        {
            // Force UI refresh - this will be handled by bindings
            // Just update status bar
            StatusTextBlock.Text = _loc["Status.Ready"];
        }

        // PE Analyzer Handlers
        private void LoadPE_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(PEFilePathTextBox.Text))
                {
                    MessageBox.Show(_loc["Error.SelectFile"], _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                peAnalyzer?.LoadPEFile(PEFilePathTextBox.Text);
                
                PEHeadersTextBlock.Text = peAnalyzer?.GetHeaders();
                PESectionsDataGrid.ItemsSource = peAnalyzer?.GetSections();
                PEImportsDataGrid.ItemsSource = peAnalyzer?.GetImports();
                PEExportsDataGrid.ItemsSource = peAnalyzer?.GetExports();

                UpdateStatus(_loc["Status.PELoaded"]);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(_loc["Error.LoadingPE"], ex.Message), _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Error);
                UpdateStatus(string.Format(_loc["Error.PELoadError"], ex.Message));
            }
        }

        private void ExportPE_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                FileName = "pe_analysis.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                peAnalyzer?.ExportAnalysis(dialog.FileName);
                UpdateStatus(string.Format(_loc["Status.AnalysisExported"], dialog.FileName));
            }
        }

        // Hex Editor Handlers
        private void LoadHex_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(HexFilePathTextBox.Text))
                {
                    var dialog = new OpenFileDialog { Filter = "All Files (*.*)|*.*" };
                    if (dialog.ShowDialog() == true)
                    {
                        HexFilePathTextBox.Text = dialog.FileName;
                    }
                    else return;
                }

                hexEditor?.LoadFile(HexFilePathTextBox.Text);
                HexEditorTextBox.Text = hexEditor?.GetHexView();
                UpdateStatus(_loc["Status.FileLoaded"]);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(_loc["Error.LoadingFile"], ex.Message), _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveHex_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(HexFilePathTextBox.Text))
                {
                    MessageBox.Show(_loc["Error.NoFileLoaded"], _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                hexEditor?.SaveFile(HexFilePathTextBox.Text, HexEditorTextBox.Text);
                UpdateStatus(_loc["Status.ChangesSaved"]);
                MessageBox.Show(_loc["Success.FileSaved"], _loc["Success.Title"], MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(_loc["Error.SaveError"], ex.Message), _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SearchHex_Click(object sender, RoutedEventArgs e)
        {
            var searchDialog = new SearchDialog();
            if (searchDialog.ShowDialog() == true)
            {
                var results = hexEditor?.Search(searchDialog.SearchPattern);
                if (results != null && results.Count > 0)
                {
                    MessageBox.Show(string.Format(_loc["Success.MatchesFound"], results.Count), _loc["Dialog.SearchResults"], MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(_loc["Success.NoMatches"], _loc["Dialog.SearchResults"], MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private void GoToOffset_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var offset = Convert.ToInt32(HexOffsetTextBox.Text.Replace("0x", ""), 16);
                hexEditor?.GoToOffset(offset);
                UpdateStatus(string.Format(_loc["Status.JumpToOffset"], HexOffsetTextBox.Text));
            }
            catch
            {
                MessageBox.Show(_loc["Error.InvalidOffset"], _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Memory Scanner Handlers
        private void RefreshProcesses_Click(object sender, RoutedEventArgs e)
        {
            ProcessListBox.ItemsSource = memoryScanner?.GetProcessList();
            NetworkProcessComboBox.ItemsSource = memoryScanner?.GetProcessList();
            UpdateStatus(_loc["Status.ProcessListUpdated"]);
        }

        private void ProcessListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProcessListBox.SelectedItem != null)
            {
                var process = ProcessListBox.SelectedItem as ProcessInfo;
                memoryScanner?.AttachToProcess(process?.Id ?? 0);
                UpdateStatus(string.Format(_loc["Status.AttachedToProcess"], process?.Name));
            }
        }

        private void FirstScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var scanType = (ScanTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "Exact Value";
                var valueType = (ValueTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "Int32";
                var value = ScanValueTextBox.Text;

                var results = memoryScanner?.FirstScan(scanType, valueType, value);
                MemoryResultsDataGrid.ItemsSource = results;
                UpdateStatus($"First scan complete. Found results: {results?.Count ?? 0}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сканирования: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void NextScan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var value = ScanValueTextBox.Text;
                var results = memoryScanner?.NextScan(value);
                MemoryResultsDataGrid.ItemsSource = results;
                UpdateStatus($"Next scan complete. Results: {results?.Count ?? 0}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сканирования: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ModifyMemory_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var memoryResult = button?.Tag as MemoryResult;
            
            var inputDialog = new InputDialog(_loc["Dialog.EnterNewValue"]);
            if (inputDialog.ShowDialog() == true)
            {
                memoryScanner?.ModifyMemory(memoryResult?.Address ?? 0, inputDialog.InputValue);
                UpdateStatus(string.Format(_loc["Status.MemoryModified"], memoryResult?.Address ?? 0));
            }
        }

        private void FreezeMemory_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var memoryResult = button?.Tag as MemoryResult;
            memoryScanner?.FreezeMemory(memoryResult?.Address ?? 0, memoryResult?.Value ?? "");
            UpdateStatus(string.Format(_loc["Status.MemoryFrozen"], memoryResult?.Address ?? 0));
        }

        // Pattern Scanner Handlers
        private void SearchPattern_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var target = (PatternTargetComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "В файле";
                var pattern = PatternTextBox.Text;

                var results = patternScanner?.SearchPattern(pattern, target == "В памяти процесса");
                PatternResultsDataGrid.ItemsSource = results;
                UpdateStatus($"Pattern search complete. Found: {results?.Count ?? 0}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Pattern search error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearPattern_Click(object sender, RoutedEventArgs e)
        {
            PatternResultsDataGrid.ItemsSource = null;
            PatternTextBox.Clear();
            UpdateStatus(_loc["Status.SearchResultsCleared"]);
        }

        // Disassembler Handlers
        private void Disassemble_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var arch = (DisasmArchComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "x64";
                var address = Convert.ToInt64(DisasmAddressTextBox.Text.Replace("0x", ""), 16);
                var size = Convert.ToInt32(DisasmSizeTextBox.Text);

                var result = disassembler?.Disassemble(arch, address, size);
                DisassemblyTextBlock.Text = result;
                UpdateStatus(_loc["Status.DisassemblyComplete"]);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(_loc["Error.DisassemblyError"], ex.Message), _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Network Monitor Handlers
        private void RefreshNetworkProcesses_Click(object sender, RoutedEventArgs e)
        {
            NetworkProcessComboBox.ItemsSource = memoryScanner?.GetProcessList();
            UpdateStatus(_loc["Status.ProcessListUpdated"]);
        }

        private void StartNetworkMonitoring_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var process = NetworkProcessComboBox.SelectedItem as ProcessInfo;
                if (process == null)
                {
                    MessageBox.Show(_loc["Error.SelectProcess"], _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                networkMonitor?.StartMonitoring(
                    process.Id,
                    FilterHTTPCheckBox.IsChecked ?? false,
                    FilterDNSCheckBox.IsChecked ?? false,
                    FilterAllTrafficCheckBox.IsChecked ?? false
                );

                networkMonitor!.OnPacketCaptured += (packet) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        var connections = networkMonitor.GetConnections();
                        NetworkConnectionsDataGrid.ItemsSource = null;
                        NetworkConnectionsDataGrid.ItemsSource = connections;
                    });
                };

                UpdateStatus(string.Format(_loc["Status.MonitoringStarted"], process.Name));
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(_loc["Error.MonitoringError"], ex.Message), _loc["Error.Title"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void StopNetworkMonitoring_Click(object sender, RoutedEventArgs e)
        {
            networkMonitor?.StopMonitoring();
            UpdateStatus(_loc["Status.MonitoringStopped"]);
        }

        private void ClearNetworkLog_Click(object sender, RoutedEventArgs e)
        {
            networkMonitor?.ClearLog();
            NetworkConnectionsDataGrid.ItemsSource = null;
            PacketDetailsTextBlock.Text = string.Empty;
            UpdateStatus(_loc["Status.NetworkLogCleared"]);
        }
    }
}
