use schema_extractor::{parse_file, run};
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
    if args.len() != 2 || args[0] != "census" {
        eprintln!("usage: schema-extractor --self-test | census <pinned-checkout>");
        std::process::exit(2);
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
