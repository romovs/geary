/* Copyright 2013 Yorba Foundation
 *
 * This software is licensed under the GNU Lesser General Public License
 * (version 2.1 or later).  See the COPYING file in this distribution.
 */

public class ComposerEmbed : Gtk.Box, ComposerContainer {
    
    private static string embed_id = "composer_embed";
    
    private ComposerWidget? composer = null;
    private ConversationViewer conversation_viewer;
    
    public Gtk.Window top_window {
        get { return (Gtk.Window) get_toplevel(); }
    }
    
    public ComposerEmbed(ConversationViewer conversation_viewer) {
        Object(orientation: Gtk.Orientation.VERTICAL);
        this.conversation_viewer = conversation_viewer;
        
        Gtk.Toolbar toolbar = new Gtk.Toolbar();
        toolbar.set_icon_size(Gtk.IconSize.MENU);
        Gtk.ToolButton close = new Gtk.ToolButton.from_stock("gtk-close");
        Gtk.ToolButton detach = new Gtk.ToolButton.from_stock("gtk-goto-top");
        Gtk.SeparatorToolItem filler = new Gtk.SeparatorToolItem();
        filler.set_expand(true);
        filler.set_draw(false);
        toolbar.insert(filler, -1);
        toolbar.insert(detach, -1);
        toolbar.insert(close, -1);
        pack_start(toolbar, false, false);
        
        close.clicked.connect(on_close);
        detach.clicked.connect(on_detach);
        conversation_viewer.web_view.create_plugin_widget.connect(on_plugin_requested);
    }
    
    public void new_composer(ComposerWidget new_composer, Geary.Email? referred) {
        if (!abandon_existing_composition(new_composer))
            return;
        
        WebKit.DOM.HTMLElement? email_element = null;
        if (referred != null)
            email_element = conversation_viewer.web_view.get_dom_document().get_element_by_id(
                conversation_viewer.get_div_id(referred.id)) as WebKit.DOM.HTMLElement;
        if (email_element == null) {
            // TODO: clear conversation list selection and put in alone
            new ComposerWindow(new_composer);
            return;
        }
        
        try {
            conversation_viewer.web_view.settings.enable_plugins = true;
            email_element.insert_adjacent_html("afterend",
                @"<embed width='100%' height='600' type='composer' id='$embed_id' />");
        } catch (Error error) {
            debug("Error creating embed element: %s", error.message);
            return;
        } finally {
            conversation_viewer.web_view.settings.enable_plugins = false;
        }
        pack_start(new_composer, true, true);
        show_all();
        present();
        this.composer = new_composer;
    }
    
    public bool abandon_existing_composition(ComposerWidget? new_composer = null) {
        if (composer == null)
            return true;
        
        present();
        AlertDialog dialog;
        if (new_composer != null)
            dialog = new AlertDialog(top_window, Gtk.MessageType.QUESTION,
                _("Do you want to discard the existing composition?"), null, Gtk.Stock.DISCARD,
                Gtk.Stock.CANCEL, _("Open New Composition Window"), Gtk.ResponseType.YES);
        else
            dialog = new AlertDialog(top_window, Gtk.MessageType.QUESTION,
                _("Do you want to discard the existing composition?"), null, Gtk.Stock.DISCARD,
                Gtk.Stock.CANCEL, _("Move Composition to New Window"), Gtk.ResponseType.YES);
        Gtk.ResponseType response = dialog.run();
        if (response == Gtk.ResponseType.OK) {
            close();
            return true;
        }
        if (new_composer != null) {
            if (response == Gtk.ResponseType.YES)
                new ComposerWindow(new_composer);
            else
                new_composer.destroy();
        } else if (response == Gtk.ResponseType.YES) {
            on_detach();
            return true;
        }
        return false;
    }
    
    private void on_close() {
        if (composer.should_close())
            close();
    }
    
    private void on_detach() {
        remove(composer);
        new ComposerWindow(composer);
        composer = null;
        close();
    }
    
    private Gtk.Widget on_plugin_requested() {
        return this;
    }
    
    public void present() {
        conversation_viewer.web_view.get_dom_document().get_element_by_id(embed_id).scroll_into_view(true);
    }
    
    public unowned Gtk.Widget get_focus() {
        return top_window.get_focus();
    }
    
    private void close() {
        if (composer != null) {
            remove(composer);
            composer.destroy();
            composer = null;
        }
        
        WebKit.DOM.Element embed = conversation_viewer.web_view.get_dom_document().get_element_by_id(embed_id);
        try{
            embed.parent_element.remove_child(embed);
        } catch (Error error) {
            warning("Could not remove embed from WebView: %s", error.message);
        }
    }
}
