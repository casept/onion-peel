use std::collections::HashMap;
use std::net::SocketAddr;

pub(crate) fn parse_transport_options(
    supported_transports: Vec<String>,
    s: String,
) -> Option<HashMap<String, HashMap<String, String>>> {
    // The options are passed in the form transport1:key=banana;transport2:rule=110;transport2:depth=3
    // Colons, semicolons and backslashes within the fields must be escaped by a backslash

    // No options provided
    if s.len() == 0 {
        return None;
    }

    // TODO: Add more thorough check to verify that the input is correct
    // For now, we simply check that we have an equivalent number of non-escaped ':' and '='
    if !input_is_valid(s.clone()) {
        // FIXME: Proper error handling
        panic!("ENV-ERROR Invalid transport options string: amount of ':' does not match amount of '='");
    }

    let split_chars: Vec<char> = vec![';', ':', '='];
    let escaped_entries = split_on_non_escaped_chars(split_chars, '\\', s);

    // Next, remove all escaping backslashes (which are all backslashes not immediately followed by a backslash)
    let entries = remove_escaping_backslashes(escaped_entries);

    // Turn this Vec<String> into the output HashMap
    let proper_format = create_output_hashmap(entries);

    // Filter out any transports that we don't support (according to the spec their k=v pairs should be ignored)
    let result = remove_unsupported_transports(proper_format.clone(), supported_transports);

    // Make sure that there was a transport we support
    if result.len() == 0 {
        return None;
    }

    fn input_is_valid(input: String) -> bool {
        let num_colons = input.matches(":").count() - input.matches(r#"\:"#).count(); // Subtract the escaped colons
        let num_equals = input.matches("=").count() - input.matches(r#"\="#).count();
        if num_colons != num_equals {
            return false;
        }
        return true;
    }
    fn split_on_non_escaped_chars(
        split_chars: Vec<char>,
        escape_char: char,
        s: String,
    ) -> Vec<String> {
        // Iterate over characters.
        // The difference to a grapheme shouldn't be a problem, as "\=:;" are all single-byte ASCII characters.
        let chars: Vec<_> = s.chars().collect();
        let mut result: Vec<String> = Vec::new();
        let mut last_character: char = ' '; // Needs to be initialized to something at all times
        let mut current_string = String::new();
        for chara in chars {
            // If the current character isn't one we should split on, save it to the string.
            if !split_chars.contains(&chara) {
                current_string.push(chara);
                last_character = chara;

            // If the current character is a split_char and the previous character was NOT escape_char,
            // begin a new string and discard the character.
            } else if split_chars.contains(&chara) && last_character != escape_char {
                result.push(current_string.clone());
                current_string.clear();
                last_character = chara;

            // If the last character was an escape character and the current character is a split_char,
            // that means that it's escaped and should be treated as a regular character.
            } else if split_chars.contains(&chara) && last_character == escape_char {
                current_string.push(chara);
                last_character = chara;
            }
        }
        // Push the last part into results as well
        result.push(current_string);
        return result;
    }

    fn remove_escaping_backslashes(items: Vec<String>) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for item in items {
            let mut new_item = String::new();
            // We should only remove backslashes that are not followed by another backslash (unescaped backslashes)
            let chars: Vec<_> = item.chars().collect();
            let mut last_char = ' ';
            for chara in chars {
                // If the current character isn't a backslash, save it to the string
                if chara != '\\' {
                    new_item.push(chara);
                    last_char = chara;

                // If the current character is a backslash and the last character was a backslash, save it
                } else if chara == '\\' && last_char == '\\' {
                    new_item.push(chara);
                    last_char = chara;
                // If the current character is a backslash and the last character was not a backslash, discard it
                } else if chara == '\\' && !(last_char == '\\') {
                    last_char = chara;
                }
            }
            result.push(new_item);
        }
        return result;
    }

    fn create_output_hashmap(entries: Vec<String>) -> HashMap<String, HashMap<String, String>> {
        // Organize everything into the output HashMap
        println!("--------------------------------------------------------------------------------------------------");
        let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
        // All legal options should now be triples of the form [transport, k, v]
        // Therefore, every 1st entry is the name of the transport,
        // every 2nd entry is the key,
        // and every 3rd entry is the value.
        let mut i = 0;
        let mut current_key = String::new();
        let mut current_subkey = String::new();
        for entry in entries {
            // Check for 1st entry
            if i % 3 == 0 {
                if !result.contains_key(&entry) {
                    result.insert(entry.clone(), HashMap::new());
                }
                current_key = entry; // So the k=v pair can be inserted into the correct top-level key's hashmap

            // Check for 2nd entry
            } else if i % 3 == 1 {
                current_subkey = entry;
            } else if i % 3 == 2 {
                // Insert the actual value
                let nested_map = result.entry(current_key.clone()).or_insert(HashMap::new()); // Insertion already happened 2 iterations ago, this is just here to fulfill the or_insert interface
                nested_map
                    .entry(current_subkey.clone())
                    .or_insert(entry.to_owned());
            }
            i = i + 1;
        }
        return result;
    }

    fn remove_unsupported_transports(
        input: HashMap<String, HashMap<String, String>>,
        supported_transports: Vec<String>,
    ) -> HashMap<String, HashMap<String, String>> {
        let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (k, v) in input {
            if supported_transports.contains(&k) {
                result.insert(k, v);
            }
        }
        return result;
    }
    return Some(result);
}

pub(crate) fn parse_bind_addresses(
    supported_transports: Vec<String>,
    s: String,
) -> HashMap<String, Option<SocketAddr>> {
    // Format example: obfs3-198.51.100.1:1984,scramblesuit-127.0.0.1:4891
    // First, split on comas which separate different plugable transports
    let mut transports_and_addresses: HashMap<String, String> = HashMap::new();
    let entries = s.split(",");
    // Next, split each of those strings on "-"
    for entry in entries {
        let transport_and_address: Vec<&str> = entry.splitn(2, "-").collect();
        transports_and_addresses.insert(
            transport_and_address[0].to_owned(),
            transport_and_address[1].to_owned(),
        );
    }

    // Next, parse each address
    let mut parsed: HashMap<String, SocketAddr> = HashMap::new();
    for (transport, addr) in transports_and_addresses {
        parsed.insert(transport, addr.parse().unwrap());
    }

    // Check which of the transports we support, discard the rest
    let mut transports_to_enable: HashMap<String, Option<SocketAddr>> = HashMap::new();
    for (transport, address) in parsed.into_iter() {
        if supported_transports.contains(&transport.to_owned()) {
            transports_to_enable.insert(transport, Some(address));
        } else {
            transports_to_enable.insert(transport, None);
        }
    }

    return transports_to_enable;
}

pub(crate) fn parse_transports_to_enable(
    supported_transports: Vec<String>,
    s: String,
) -> Option<Vec<String>> {
    // The transports are a coma-separated list
    let transports_requested = s.split(",");

    // Check which of the transports we support, ignore the rest
    let mut transports_to_enable: Vec<String> = Vec::new();
    for transport in transports_requested {
        if supported_transports.contains(&transport.to_owned()) {
            transports_to_enable.push(transport.to_string());
        }
    }

    if transports_to_enable.len() > 0 {
        return Some(transports_to_enable);
    } else {
        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test parse_bind_addresses
    #[test]
    fn test_parse_bind_addresses_multiple_entries() {
        let addr_string = "obfs3-198.51.100.1:1984,scramblesuit-127.0.0.1:4891".to_string();
        let mut expected_result: HashMap<String, Option<SocketAddr>> = HashMap::new();
        expected_result.insert(
            "obfs3".to_string(),
            Some("198.51.100.1:1984".parse().unwrap()),
        );
        expected_result.insert(
            "scramblesuit".to_string(),
            Some("127.0.0.1:4891".parse().unwrap()),
        );
        assert_eq!(
            expected_result,
            parse_bind_addresses(
                vec!["obfs3".to_string(), "scramblesuit".to_string()],
                addr_string
            )
        );
    }

    #[test]
    fn test_parse_bind_addresses_single_entry() {
        let addr_string = "obfs3-198.51.100.1:1984".to_string();
        let mut expected_result: HashMap<String, Option<SocketAddr>> = HashMap::new();
        expected_result.insert(
            "obfs3".to_string(),
            Some("198.51.100.1:1984".parse().unwrap()),
        );
        assert_eq!(
            expected_result,
            parse_bind_addresses(vec!["obfs3".to_string()], addr_string)
        );
    }

    #[test]
    #[should_panic]
    fn test_parse_bind_addresses_invalid_ip() {
        let addr_string = "obfs3-example.com:1984".to_string();
        parse_bind_addresses(vec!["obfs3".to_string()], addr_string);
    }

    #[test]
    #[should_panic]
    fn test_parse_bind_addresses_invalid_port() {
        let addr_string = "198.51.100.1:DEADF00".to_string();
        parse_bind_addresses(vec!["obfs3".to_string()], addr_string);
    }

    // Test parse_transport_options
    #[test]
    fn test_parse_transport_options_no_options() {
        assert_eq!(
            None,
            parse_transport_options(vec!["transport1".to_string()], "".to_string())
        );
    }
    #[test]
    fn test_parse_transport_options_single_transport_single_option() {
        let options = "transport1:key=banana".to_string();
        let mut expected_result: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut transport1_result: HashMap<String, String> = HashMap::new();
        transport1_result.insert("key".to_string(), "banana".to_string());
        expected_result.insert("transport1".to_string(), transport1_result);
        assert_eq!(
            Some(expected_result),
            parse_transport_options(vec!["transport1".to_string()], options)
        );
    }
    #[test]
    fn test_parse_transport_options_single_transport_multiple_options() {
        let options = "transport1:key=banana;transport1:rule=110;transport1:depth=3".to_string();
        let mut expected_result: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut transport1_result: HashMap<String, String> = HashMap::new();
        transport1_result.insert("key".to_string(), "banana".to_string());
        transport1_result.insert("rule".to_string(), "110".to_string());
        transport1_result.insert("depth".to_string(), "3".to_string());
        expected_result.insert("transport1".to_string(), transport1_result);
        assert_eq!(
            Some(expected_result),
            parse_transport_options(vec!["transport1".to_string()], options)
        );
    }
    #[test]
    fn test_parse_transport_options_multiple_transports_single_option() {
        let options = "transport1:key=banana;transport2:rule=110;transport3:depth=3".to_string();
        let mut expected_result: HashMap<String, HashMap<String, String>> = HashMap::new();

        let mut transport1_result: HashMap<String, String> = HashMap::new();
        transport1_result.insert("key".to_string(), "banana".to_string());
        let mut transport2_result: HashMap<String, String> = HashMap::new();
        transport2_result.insert("rule".to_string(), "110".to_string());
        let mut transport3_result: HashMap<String, String> = HashMap::new();
        transport3_result.insert("depth".to_string(), "3".to_string());

        expected_result.insert("transport1".to_string(), transport1_result);
        expected_result.insert("transport2".to_string(), transport2_result);
        expected_result.insert("transport3".to_string(), transport3_result);

        let transports = vec![
            "transport1".to_string(),
            "transport2".to_string(),
            "transport3".to_string(),
        ];
        assert_eq!(
            Some(expected_result),
            parse_transport_options(transports, options)
        );
    }
    #[test]
    fn test_parse_transport_options_multiple_transports_multiple_options() {
        let options =
            "transport1:key=banana;transport1:rule=110;transport2:depth=3;transport2:breadth=foo"
                .to_string();

        let mut expected_result: HashMap<String, HashMap<String, String>> = HashMap::new();

        let mut transport1_result: HashMap<String, String> = HashMap::new();
        transport1_result.insert("key".to_string(), "banana".to_string());
        transport1_result.insert("rule".to_string(), "110".to_string());
        let mut transport2_result: HashMap<String, String> = HashMap::new();
        transport2_result.insert("depth".to_string(), "3".to_string());
        transport2_result.insert("breadth".to_string(), "foo".to_string());

        expected_result.insert("transport1".to_string(), transport1_result);
        expected_result.insert("transport2".to_string(), transport2_result);

        let supported_transports = vec!["transport1".to_string(), "transport2".to_string()];
        assert_eq!(
            Some(expected_result),
            parse_transport_options(supported_transports, options)
        );
    }
    #[test]
    fn test_parse_transport_options_escaped_characters() {
        let options =
            r#"transport1:key=ba\=nana;transport2:ru\\le=110;transport2:dep\:th=3"#.to_string();
        let mut expected_result: HashMap<String, HashMap<String, String>> = HashMap::new();

        let mut transport1_result: HashMap<String, String> = HashMap::new();
        transport1_result.insert("key".to_string(), "ba=nana".to_string());
        let mut transport2_result: HashMap<String, String> = HashMap::new();
        transport2_result.insert(r#"ru\le"#.to_string(), "110".to_string());
        transport2_result.insert(r#"dep:th"#.to_string(), "3".to_string());

        expected_result.insert("transport1".to_string(), transport1_result);
        expected_result.insert("transport2".to_string(), transport2_result);

        let supported_transports = vec!["transport1".to_string(), "transport2".to_string()];
        assert_eq!(
            Some(expected_result),
            parse_transport_options(supported_transports, options)
        );
    }
    #[test]
    #[should_panic]
    fn test_parse_transport_options_missing_colon_separator() {
        let options = "transport1key=banana".to_string();
        let supported_transports = vec!["transport1".to_string()];
        parse_transport_options(supported_transports, options);
    }
    #[test]
    #[should_panic]
    fn test_parse_transport_options_missing_equals_separator() {
        let options = "transport1:keybanana".to_string();
        let supported_transports = vec!["transport1".to_string()];
        parse_transport_options(supported_transports, options);
    }

    #[test]
    fn test_parse_transport_options_unsupported_transport() {
        let options = "transport1:key=banana".to_string();
        let supported_transports = vec!["transport2".to_string()];
        assert_eq!(None, parse_transport_options(supported_transports, options));
    }

    // Test get_transports_to_enable
    #[test]
    fn test_get_transports_to_enable_no_transports() {
        let test_string = "".to_string();
        let supported_transports = vec!["obfs3".to_string()];
        assert_eq!(
            None,
            parse_transports_to_enable(supported_transports, test_string)
        );
    }

    #[test]
    fn test_get_transports_to_enable_one_transport() {
        let test_string = "obfs3,transport2".to_string();
        let mut expected_result: Vec<String> = Vec::new();
        expected_result.push("obfs3".to_string());
        let supported_transports = vec!["obfs3".to_string()];
        assert_eq!(
            Some(expected_result),
            parse_transports_to_enable(supported_transports, test_string)
        );
    }
    #[test]
    fn test_get_transports_to_enable_multiple_transports() {
        let test_string = "obfs3,transport1,transport2".to_string();
        let mut expected_result: Vec<String> = Vec::new();
        expected_result.push("obfs3".to_string());
        expected_result.push("transport1".to_string());
        let supported_transports = vec!["obfs3".to_string(), "transport1".to_string()];
        assert_eq!(
            Some(expected_result),
            parse_transports_to_enable(supported_transports, test_string)
        );
    }
}
