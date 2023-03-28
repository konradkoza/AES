module p.lodz.kryptografia {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;

    opens p.lodz.kryptografia to javafx.fxml;
    exports p.lodz.kryptografia;
}