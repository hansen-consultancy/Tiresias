using System.Windows;
using System.Windows.Controls;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>
/// The details of a list's selected row, placed below the list: bind <see cref="Fields"/> to the
/// selected row's fields. Hidden while nothing is selected.
/// </summary>
public partial class DetailsPanel : UserControl
{
    public static readonly DependencyProperty FieldsProperty = DependencyProperty.Register(
        nameof(Fields), typeof(IEnumerable<DetailField>), typeof(DetailsPanel), new(null, (d, _) => ((DetailsPanel)d).Show()));

    public DetailsPanel() => InitializeComponent();

    public IEnumerable<DetailField>? Fields
    {
        get => (IEnumerable<DetailField>?)GetValue(FieldsProperty);
        set => SetValue(FieldsProperty, value);
    }

    void Show()
    {
        var shown = DetailText.Shown(Fields ?? []);
        Lines.ItemsSource = shown;
        Card.Visibility = shown.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    void OnCopy(object sender, RoutedEventArgs e) => Clipboard.SetText(DetailText.Format(Fields ?? []));
}
