using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Tiresias.App.Views;

/// <summary>
/// A list whose rows hold their own controls (a check box, buttons): <c>PickList.SelectsFocusedRow</c>
/// selects the row a click or Tab lands in, which a <see cref="ListBox"/> otherwise leaves to clicks on
/// the row's background, so the details panel below follows whatever was last touched.
/// </summary>
public static class PickList
{
    public static readonly DependencyProperty SelectsFocusedRowProperty = DependencyProperty.RegisterAttached(
        "SelectsFocusedRow", typeof(bool), typeof(PickList), new(false, OnChanged));

    public static bool GetSelectsFocusedRow(DependencyObject d) => (bool)d.GetValue(SelectsFocusedRowProperty);

    public static void SetSelectsFocusedRow(DependencyObject d, bool value) => d.SetValue(SelectsFocusedRowProperty, value);

    static void OnChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ListBox list)
            return;
        list.GotKeyboardFocus -= OnFocus;
        if ((bool)e.NewValue)
            list.GotKeyboardFocus += OnFocus;
    }

    static void OnFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (e.NewFocus is DependencyObject focused && ItemsControl.ContainerFromElement((ListBox)sender, focused) is ListBoxItem row)
            row.IsSelected = true;
    }
}
