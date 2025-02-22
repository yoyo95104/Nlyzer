use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Button, Label, Box as GtkBox, Orientation, Align, Grid};
use tokio::sync::watch;
use glib::{MainContext, Sender};
use std::sync::Arc;
mod lib;
use lib::start_scan;

const APP_ID: &str = "org.Nlyzer.app";

#[tokio::main]
async fn main() {
    let app = Application::builder()
        .application_id(APP_ID)
        .build();

    app.connect_activate(|app|{ 
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Nlyzer")
            .default_width(600)
            .default_height(400)
            .build();
        let label = Label::new(Some("Welcome to Nlyzer, The world's fastest and safest network analyzer. Please Proceed."));
        label.set_halign(Align::Center);
        let scan_button = Button::with_label("Scan");
        let stop_button = Button::with_label("Stop");
        let info = Label::new(None);
        info.set_halign(Align::Center);
        let grid = Grid::new();
        grid.set_column_spacing(10);
        grid.set_row_spacing(5);
        let container = GtkBox::new(Orientation::Vertical, 10);
        container.append(&label);
        container.append(&scan_button);
        container.append(&stop_button);
        container.append(&info);
        container.append(&grid);
        window.set_child(Some(&container));
        let (sender, receiver) = MainContext::channel(glib::PRIORITY_DEFAULT);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        scan_button.connect_clicked(move |_| {
            let sender = sender.clone();
            let cancel_rx = cancel_rx.clone();
            tokio::spawn(async move {
                start_scan(cancel_rx, sender).await;
            });
        });
        stop_button.connect_clicked(move |_| {
            let _ = cancel_tx.send(true);
        });
        receiver.attach(None, move |summary| {
            info.set_text(&summary);
            glib::Continue(true)
        });
        window.show();
    });
    app.run();
}
