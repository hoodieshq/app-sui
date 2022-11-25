rec {
  alamgu = import ./dep/alamgu {};

  inherit (alamgu) lib pkgs crate2nix;

  appName = "rust-app";

  makeApp = { rootFeatures ? [ "default" ], release ? true, device }:
    let collection = alamgu.perDevice.${device};
    in import ./Cargo.nix {
      inherit rootFeatures release;
      pkgs = collection.ledgerPkgs;
      buildRustCrateForPkgs = pkgs: let
        fun = collection.buildRustCrateForPkgsWrapper
          pkgs
          ((collection.buildRustCrateForPkgsLedger pkgs).override {
            defaultCrateOverrides = pkgs.defaultCrateOverrides // {
              ${appName} = attrs: let
                sdk = lib.findFirst (p: lib.hasPrefix "rust_nanos_sdk" p.name) (builtins.throw "no sdk!") attrs.dependencies;
              in {
                preHook = collection.gccLibsPreHook;
                extraRustcOpts = attrs.extraRustcOpts or [] ++ [
                  "-C" "linker=${pkgs.stdenv.cc.targetPrefix}clang"
                  "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/link.ld"
                ] ++ (if (device == "nanos") then
                  [ "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/nanos_layout.ld" ]
                else if (device == "nanosplus") then
                  [ "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/nanosplus_layout.ld" ]
                else if (device == "nanox") then
                  [ "-C" "link-arg=-T${sdk.lib}/lib/nanos_sdk.out/nanox_layout.ld" ]
                else throw ("Unknown target device: `${device}'"));
              };
            };
          });
      in
        args: fun (args // lib.optionalAttrs pkgs.stdenv.hostPlatform.isAarch32 {
          dependencies = map (d: d // { stdlib = true; }) [
            collection.ledgerCore
            collection.ledgerCompilerBuiltins
          ] ++ args.dependencies;
        });
  };

  makeTarSrc = { appExe, device }: pkgs.runCommandCC "make-tar-src-${device}" {
    nativeBuildInputs = [
      alamgu.cargo-ledger
      alamgu.ledgerRustPlatform.rust.cargo
    ];
  } (alamgu.cargoLedgerPreHook + ''

    cp ${./rust-app/Cargo.toml} ./Cargo.toml
    # So cargo knows it's a binary
    mkdir src
    touch src/main.rs

    cargo-ledger --use-prebuilt ${appExe} --hex-next-to-json ledger ${device}

    dest=$out/${appName}
    mkdir -p $dest

    # Create a file to indicate what device this is for
    echo ${device} > $dest/device
    cp app_${device}.json $dest/app.json
    cp app.hex $dest
    cp ${./tarball-default.nix} $dest/default.nix
    cp ${./tarball-shell.nix} $dest/shell.nix
    cp ${./rust-app/crab.gif} $dest/crab.gif
    cp ${./rust-app/crab-small.gif} $dest/crab-small.gif
  '');

  testPackage = (import ./ts-tests/override.nix { inherit pkgs; }).package;

  testScript = pkgs.writeShellScriptBin "mocha-wrapper" ''
    cd ${testPackage}/lib/node_modules/*/
    export NO_UPDATE_NOTIFIER=true
    exec ${pkgs.nodejs-14_x}/bin/npm --offline test -- "$@"
  '';

  apiPort = 5000;

  runTests = { appExe, device, variant ? "", speculosCmd }: pkgs.runCommandNoCC "run-tests-${device}${variant}" {
    nativeBuildInputs = [
      pkgs.wget alamgu.speculos.speculos testScript
    ];
  } ''
    mkdir $out
    (
    ${speculosCmd} ${appExe} --display headless &
    SPECULOS=$!

    until wget -O/dev/null -o/dev/null http://localhost:${toString apiPort}; do sleep 0.1; done;

    ${testScript}/bin/mocha-wrapper
    rv=$?
    kill -9 $SPECULOS
    exit $rv) | tee $out/short |& tee $out/full &
    TESTS=$!
    (sleep 3m; kill $TESTS) &
    TESTKILLER=$!
    wait $TESTS
    rv=$?
    kill $TESTKILLER
    cat $out/short
    exit $rv
  '';

  appForDevice = device : rec {
    rootCrate = (makeApp { inherit device; }).rootCrate.build;
    rootCrate-with-logging = (makeApp {
      inherit device;
      release = false;
      rootFeatures = [ "default" "speculos" "extra_debug" ];
    }).rootCrate.build;

    appExe = rootCrate + "/bin/" + appName;

    tarSrc = makeTarSrc { inherit appExe device; };
    tarball = pkgs.runCommandNoCC "app-tarball-${device}.tar.gz" { } ''
      tar -czvhf $out -C ${tarSrc} ${appName}
    '';

    loadApp = pkgs.writeScriptBin "load-app" ''
      #!/usr/bin/env bash
      cd ${tarSrc}/${appName}
      ${alamgu.ledgerctl}/bin/ledgerctl install -f ${tarSrc}/${appName}/app.json
    '';

    speculosCmd = {
      nanos = "speculos -m nanos";
      nanosplus = "speculos  -m nanosp -k 1.0.3";
      nanox = "speculos -m nanox";
    }.${device} or (throw "Unknown target device: `${device}'");

    test = runTests { inherit appExe speculosCmd device; };
    test-with-loging = runTests {
      inherit speculosCmd device;
      appExe = rootCrate-with-logging + "/bin/" + appName;
      variant = "-with-logging";
    };

    appShell = pkgs.mkShell {
      packages = [ loadApp alamgu.generic-cli pkgs.jq ];
    };
  };

  nanos = appForDevice "nanos";
  nanosplus = appForDevice "nanosplus";
  nanox = appForDevice "nanox";

  inherit (pkgs.nodePackages) node2nix;

}
