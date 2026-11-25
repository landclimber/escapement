{
  description = "escapement_core_module: Escapement's vesting module for Logos Core (prototype)";

  # The builder supplies the code generator and the logos-rust-sdk source the crate links. Pinned to the commit
  # Ferrata's modules are built with (the same flake.lock).
  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/5f74cdb3cecacde054c68d72fcc0d2cfe2195900";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
