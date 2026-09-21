use ciphera_core::SecretInput;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse_env_file<P: AsRef<Path>>(path: P) -> Result<Vec<SecretInput>, String> {
    let file =
        File::open(&path).map_err(|e| format!("Failed to open file {:?}: {}", path.as_ref(), e))?;
    let reader = BufReader::new(file);
    let mut secrets = Vec::new();

    for (index, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| format!("Error reading line {}: {}", index + 1, e))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let clean_key = key.trim().to_string();
            let clean_value = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();

            if !clean_key.is_empty() {
                secrets.push(SecretInput {
                    key: clean_key,
                    value: clean_value,
                });
            }
        }
    }

    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_env_file() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "# Comment line").unwrap();
        writeln!(temp).unwrap();
        writeln!(temp, "DB_HOST=localhost").unwrap();
        writeln!(temp, "DB_PASS=\"secret_pass123\"").unwrap();
        writeln!(temp, "API_KEY='xyz_789'").unwrap();

        let secrets = parse_env_file(temp.path()).unwrap();
        assert_eq!(secrets.len(), 3);
        assert_eq!(secrets[0].key, "DB_HOST");
        assert_eq!(secrets[0].value, "localhost");
        assert_eq!(secrets[1].key, "DB_PASS");
        assert_eq!(secrets[1].value, "secret_pass123");
        assert_eq!(secrets[2].key, "API_KEY");
        assert_eq!(secrets[2].value, "xyz_789");
    }
}
