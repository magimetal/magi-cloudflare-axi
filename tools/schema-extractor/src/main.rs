use schema_extractor::{compiler, parse_file, run, validation};
use std::{env, path::Path};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.as_slice() == ["--self-test"] {
        let source = include_str!("../fixtures/registrations.ts");
        let records =
            parse_file("fixture.ts", source, "fixture").expect("typed fixture must parse");
        assert_eq!(
            records.len(),
            15,
            "{:?}",
            records
                .iter()
                .map(|record| &record.name)
                .collect::<Vec<_>>()
        );
        for expected in [
            "context_direct",
            "dex_local",
            "casb_one",
            "casb_two",
            "inline_app",
            "syntax_features",
            "shadowed_z",
            "indirect_options",
            "spread_options",
            "quoted_options",
        ] {
            assert!(records.iter().any(|record| record.name == expected));
        }
        for rejected in [
            "foreign_shadowed",
            "foreign_context",
            "foreign_method",
            "foreign_app",
            "foreign_import",
            "foreign_dex_context",
            "regex_fake",
        ] {
            assert!(records.iter().all(|record| record.name != rejected));
        }
        println!("schema-extractor self-test: ok");
        return;
    }
    if args.len() != 2 || !matches!(args[0].as_str(), "census" | "compile" | "validate") {
        eprintln!(
            "usage: schema-extractor --self-test | census <pinned-checkout> | compile <pinned-checkout> | validate <bundle.json>"
        );
        std::process::exit(2);
    }
    if args[0] == "validate" {
        match validation::validate_bundle_file(Path::new(&args[1])) {
            Ok(envelope) => println!(
                "{}",
                serde_json::to_string_pretty(&envelope).expect("fixture envelope serialization")
            ),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args[0] == "compile" {
        match run(Path::new(&args[1])) {
            Ok(census) => {
                let bundle = compiler::compile(&census);
                let invalid = census.source_count != 172
                    || census.catalog_count != 172
                    || census.source_count != census.catalog_count
                    || !census.duplicates.is_empty()
                    || !census.missing.is_empty()
                    || !census.extra.is_empty()
                    || bundle.contracts.len() != 172
                    || bundle.candidate_complete_count != 168
                    || bundle.candidate_zero_input_count != 4
                    || bundle.unresolved_count != 0;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&bundle).expect("schema bundle serialization")
                );
                if invalid {
                    std::process::exit(1);
                }
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    match run(Path::new(&args[1])) {
        Ok(census) => {
            let invalid = census.source_count != census.catalog_count
                || !census.duplicates.is_empty()
                || !census.missing.is_empty()
                || !census.extra.is_empty();
            println!(
                "{}",
                serde_json::to_string_pretty(&census).expect("census serialization")
            );
            if invalid {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
