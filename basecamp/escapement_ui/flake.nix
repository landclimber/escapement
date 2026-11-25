{
  description = "escapement_ui: Escapement's Logos mini-app (ui_qml module, prototype)";

  # Pinned to the builder commit escapement_core_module uses (the same flake.lock).
  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/5f74cdb3cecacde054c68d72fcc0d2cfe2195900";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosQmlModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
