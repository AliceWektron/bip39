// Imports and Dependencies
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    style::{Color, ResetColor, SetForegroundColor},
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, 
        disable_raw_mode, enable_raw_mode,
    },
    ExecutableCommand,
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color as TuiColor, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row as TuiRow, Table as TuiTable, Wrap},
    Terminal,
};
use terminal_size::{Width, Height};

use std::{
    fs::File,
    io::{self, BufRead, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};

use argon2::{Argon2, Algorithm, Params, Version};
use sha2::{Digest, Sha256};
use tiny_keccak::Hasher;
use ed25519_dalek::{SigningKey, VerifyingKey};
use slip10::{derive_key_from_path, Curve, BIP32Path};
use sskr::{sskr_combine, sskr_generate, GroupSpec, Secret, Spec};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::{PublicKey, Secp256k1},
    Address, Network,
};
use bs58;
use bip39;

use rand::{rngs::OsRng, seq::SliceRandom, Rng};

use serde::{Deserialize, Serialize};

use qrcode::QrCode;
use image::Luma;
use viuer;

// Structs and Data Types
#[derive(Serialize, Deserialize)]
struct SeedBackup {
    seed_phrase: String,
    passphrase: String,
    sskr: SskrBackup,
    entropy: String,
    bip39_seed: String,
    bip32_root_key: String,
    recovery_info: String,
}

#[derive(Serialize, Deserialize)]
struct SskrBackup {
    groups: Vec<Vec<Share>>,
}

#[derive(Serialize, Deserialize)]
struct Share {
    share_hex: String,
    mnemonic: String,
}

#[derive(Clone)]
struct ThemeColors {
    header: Color,
    highlighted: Color,
    final_output: Color,
    candidate_header: Color,
    position_label: Color,
    input_prompt: Color,
    random_message: Color,
    error: Color,
}

#[derive(Debug)]
struct AddressEntry {
    index: u32,
    address: String,
    pubkey: String,
    privkey: String,
}

// Theming & Color Conversion
fn get_catppuccin_mocha_theme() -> ThemeColors {
    ThemeColors {
        header: Color::Rgb { r: 198, g: 160, b: 246 },
        highlighted: Color::Rgb { r: 255, g: 140, b: 0 },
        final_output: Color::Rgb { r: 166, g: 218, b: 149 },
        candidate_header: Color::Rgb { r: 183, g: 189, b: 248 },
        position_label: Color::Rgb { r: 238, g: 212, b: 159 },
        input_prompt: Color::Rgb { r: 145, g: 215, b: 227 },
        random_message: Color::Rgb { r: 138, g: 173, b: 244 },
        error: Color::Rgb { r: 237, g: 135, b: 150 },
    }
}

fn convert_color(color: Color) -> TuiColor {
    match color {
        Color::Rgb { r, g, b } => TuiColor::Rgb(r, g, b),
        _ => TuiColor::Reset,
    }
}

// Bit Manipulation Helpers
fn bits_from_u16(num: u16, bits: usize) -> Vec<bool> {
    let mut bits_vec = Vec::with_capacity(bits);
    for i in (0..bits).rev() {
        bits_vec.push((num >> i) & 1 == 1);
    }
    bits_vec
}

fn bits_to_u16(bits: &[bool]) -> u16 {
    bits.iter().fold(0, |acc, &bit| (acc << 1) | if bit { 1 } else { 0 })
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | if bit { 1 } else { 0 };
        }
        if chunk.len() < 8 {
            byte <<= 8 - chunk.len();
        }
        bytes.push(byte);
    }
    bytes
}

// Encryption, Decryption & Security Functions
fn encrypt_data(plaintext: &str, password: &str) -> Vec<u8> {
    let mut rng = OsRng;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);

    let params = Params::new(256 * 1024, 100, 1, Some(32)).expect("Invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .expect("Key derivation failed");

    lock_sensitive_data(&mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");
    let nonce_ga = Nonce::<Aes256Gcm>::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext.as_bytes())
        .expect("Encryption failure!");
    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    output
}

fn decrypt_data(ciphertext: &[u8], password: &str) -> Result<String, String> {
    if ciphertext.len() < 28 {
        return Err("Ciphertext too short".into());
    }
    let salt = &ciphertext[0..16];
    let nonce = &ciphertext[16..28];
    let actual_ciphertext = &ciphertext[28..];

    let params = Params::new(256 * 1024, 100, 1, Some(32))
        .map_err(|_| "Invalid Argon2 params".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "Key derivation failed".to_string())?;

    lock_sensitive_data(&mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Invalid key".to_string())?;
    let nonce_ga = Nonce::<Aes256Gcm>::from_slice(nonce);
    let decrypted_bytes = cipher
        .decrypt(nonce_ga, actual_ciphertext)
        .map_err(|_| "Decryption failed".to_string())?;
    String::from_utf8(decrypted_bytes)
        .map_err(|_| "Decrypted data is not valid UTF-8".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_sensitive_data(data: &mut [u8]) {
    use memsec::mlock;
    let locked = unsafe { mlock(data.as_mut_ptr(), data.len()) };
    if !locked {
         eprintln!("Warning: Failed to lock memory");
    }
}

#[cfg(target_os = "windows")]
fn lock_sensitive_data(data: &mut [u8]) {
    use std::ptr::null_mut;
    use winapi::um::memoryapi::VirtualLock;
    use winapi::shared::minwindef::LPVOID;
    let ret = unsafe { VirtualLock(data.as_mut_ptr() as LPVOID, data.len()) };
    if ret == 0 {
        eprintln!("Warning: Failed to lock memory using VirtualLock");
    }
}

// Blockchain Address Generation Functions
fn ethereum_address_from_pubkey(pubkey: &PublicKey) -> String {
    let uncompressed = pubkey.serialize_uncompressed();
    let pubkey_bytes = &uncompressed[1..];
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(pubkey_bytes);
    keccak.finalize(&mut hash);
    let address_bytes = &hash[12..];
    let address = hex::encode(address_bytes);
    to_checksum_address(&address)
}

fn to_checksum_address(address: &str) -> String {
    let address_lower = address.to_lowercase();
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(address_lower.as_bytes());
    keccak.finalize(&mut hash);
    let mut checksum_address = String::from("0x");
    for (i, ch) in address_lower.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 { (hash_byte >> 4) & 0xF } else { hash_byte & 0xF };
        if nibble >= 8 {
            checksum_address.push(ch.to_ascii_uppercase());
        } else {
            checksum_address.push(ch);
        }
    }
    checksum_address
}

fn xrp_address_from_pubkey(pubkey: &PublicKey) -> String {
    let pubkey_bytes = pubkey.serialize();
    let sha256_hash = Sha256::digest(&pubkey_bytes);
    use bitcoin::hashes::{ripemd160, Hash};
    let ripemd_hash = ripemd160::Hash::hash(&sha256_hash);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&ripemd_hash[..]);
    let double_hash = Sha256::digest(&Sha256::digest(&payload));
    let checksum = &double_hash[0..4];
    payload.extend_from_slice(checksum);
    let alphabet = bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz").unwrap();
    bs58::encode(payload).with_alphabet(&alphabet).into_string()
}

// Mnemonic & SSKR Helpers
fn share_to_mnemonic(share: &[u8], language: bip39::Language) -> String {
    let share_len = share.len() as u16;
    let mut bit_vec = bits_from_u16(share_len, 16);
    for &byte in share {
        for i in (0..8).rev() {
            bit_vec.push((byte >> i) & 1 == 1);
        }
    }
    while bit_vec.len() % 11 != 0 {
        bit_vec.push(false);
    }
    let wordlist = language.word_list();
    let mut mnemonic_words = Vec::new();
    for chunk in bit_vec.chunks(11) {
        let index = bits_to_u16(chunk) as usize;
        mnemonic_words.push(wordlist[index]);
    }
    mnemonic_words.join(" ")
}

fn mnemonic_to_share(mnemonic: &str, language: bip39::Language) -> Option<Vec<u8>> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let wordlist = language.word_list();
    let mut bits = Vec::new();
    for word in words {
        let index = wordlist.iter().position(|&w| w == word)?;
        let index_bits = bits_from_u16(index as u16, 11);
        bits.extend(index_bits);
    }
    if bits.len() < 16 {
        return None;
    }
    let share_len_bits = &bits[0..16];
    let share_len = bits_to_u16(share_len_bits) as usize;
    let required_bits = share_len * 8;
    if bits.len() < 16 + required_bits {
        return None;
    }
    let share_bits = &bits[16..(16 + required_bits)];
    let share_bytes = bits_to_bytes(share_bits);
    Some(share_bytes)
}

fn validate_mnemonic(mnemonic: &str, language: bip39::Language) -> Result<(), String> {
    let wordlist = language.word_list();
    for (i, word) in mnemonic.split_whitespace().enumerate() {
        if !wordlist.contains(&word) {
            return Err(format!("Mnemonic contains an unknown word at position {}: {}", i + 1, word));
        }
    }
    Ok(())
}

fn language_from_choice(_choice: u8) -> bip39::Language {
    bip39::Language::English
}

// User Input & UI Functions
fn prompt_user_input(prompt: &str, color: Color) -> String {
    let mut stdout = io::stdout();
    stdout.execute(SetForegroundColor(color)).unwrap();
    print!("{}", prompt);
    stdout.execute(ResetColor).unwrap();
    io::stdout().flush().unwrap();
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buffer = Vec::new();
    handle.read_until(b'\n', &mut buffer).expect("Failed to read input");
    String::from_utf8_lossy(&buffer).trim().to_string()
}

fn prompt_single_key(prompt: &str, color: Color) -> char {
    let mut stdout = io::stdout();
    enable_raw_mode().unwrap();
    stdout.execute(Clear(ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    stdout.execute(SetForegroundColor(color)).unwrap();
    let lines: Vec<&str> = prompt.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        stdout.execute(Clear(ClearType::CurrentLine)).unwrap();
        stdout.execute(cursor::MoveToColumn(0)).unwrap();
        if i == lines.len() - 1 {
            print!("{}", line);
        } else {
            println!("{}", line);
        }
    }
    stdout.execute(ResetColor).unwrap();
    stdout.flush().unwrap();
    let key = loop {
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Char(c) => break c,
                    _ => break '?',
                }
            }
        }
    };
    disable_raw_mode().unwrap();
    key
}

fn await_key(seconds: u64, theme_colors: &ThemeColors) {
    let mut stdout = io::stdout();
    let start = Instant::now();
    let mut remaining = seconds;
    loop {
        stdout.execute(SetForegroundColor(theme_colors.input_prompt)).unwrap();
        stdout.execute(Clear(ClearType::CurrentLine)).unwrap();
        print!(
            "\rPress any key to skip now, or wait {} second{}",
            remaining,
            if remaining == 1 { "" } else { "s" }
        );
        stdout.flush().unwrap();
        stdout.execute(ResetColor).unwrap();
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(_) = event::read().unwrap() {
                break;
            }
        }
        if start.elapsed().as_secs() >= seconds {
            break;
        }
        remaining = seconds.saturating_sub(start.elapsed().as_secs());
    }
    println!();
}

fn hidden_input(prompt: &str, color: Color) -> String {
    use crossterm::{
        event::{self, KeyCode},
        style::{SetForegroundColor, ResetColor},
        cursor,
        terminal::{enable_raw_mode, disable_raw_mode},
    };
    let mut stdout = io::stdout();
    stdout.execute(SetForegroundColor(color)).unwrap();
    print!("{}", prompt);
    stdout.execute(ResetColor).unwrap();
    stdout.flush().unwrap();

    enable_raw_mode().unwrap();
    let mut password = String::new();
    loop {
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key_event) = event::read().unwrap() {
                match key_event.code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        password.push(c);
                        print!("*");
                        stdout.flush().unwrap();
                    },
                    KeyCode::Backspace => {
                        if !password.is_empty() {
                            password.pop();
                            stdout.execute(cursor::MoveLeft(1)).unwrap();
                            print!(" ");
                            stdout.execute(cursor::MoveLeft(1)).unwrap();
                            stdout.flush().unwrap();
                        }
                    },
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode().unwrap();
    println!();
    password.trim().to_string()
}

fn run_backup_text_ui(
    backup: SeedBackup,
    theme_colors: ThemeColors,
    title: &str,
    show_save: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut mask_state = true;
    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(90), Constraint::Percentage(10)].as_ref())
                .split(f.area());
            let styled_text = format_backup_styled(&backup, mask_state, theme_colors.final_output);
            let paragraph = Paragraph::new(styled_text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(title),
                )
                .wrap(Wrap { trim: false });
            f.render_widget(paragraph, chunks[0]);
            let note_text = if show_save {
                "Press [Tab] to toggle sensitive value visibility, [s] to save JSON file, [q] to exit."
            } else {
                "Press [Tab] to toggle sensitive value visibility, [q] to exit."
            };
            let note = Paragraph::new(note_text)
                .style(Style::default().fg(TuiColor::White));
            f.render_widget(note, chunks[1]);
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Tab => mask_state = !mask_state,
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') if show_save => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        let mut stdout = io::stdout();
                        stdout.execute(Clear(ClearType::All))?;
                        stdout.execute(cursor::MoveTo(0, 0))?;
                        let encryption_password = loop {
                            let pass1 = hidden_input(
                                "\nEnter a password to encrypt your JSON file: ",
                                theme_colors.input_prompt,
                            );
                            let pass2 = hidden_input("Re-enter password to confirm: ", theme_colors.input_prompt);
                            if pass1 == pass2 {
                                break pass1;
                            } else {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Passwords do not match. Please try again.");
                                stdout.execute(ResetColor)?;
                            }
                        };
                        let json_data = serde_json::to_string_pretty(&backup)?;
                        let encrypted_json = encrypt_data(&json_data, &encryption_password);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            let mut file = std::fs::OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .mode(0o600)
                                .open("seed_backup.json.enc")?;
                            file.write_all(&encrypted_json)?;
                        }
                        #[cfg(windows)]
                        {
                            let mut file = File::create("seed_backup.json.enc")?;
                            file.write_all(&encrypted_json)?;
                        }
                        stdout.execute(Clear(ClearType::All))?;
                        stdout.execute(cursor::MoveTo(0, 0))?;
                        print!("Encrypted JSON file saved as ");
                        stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                        print!("'seed_backup.json.enc'");
                        stdout.execute(ResetColor)?;
                        println!();
                        println!("Press any key to exit.");
                        enable_raw_mode()?;
                        let _ = event::read()?;
                        disable_raw_mode()?;
                        return Ok(());
                    },
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn format_backup_styled(
    backup: &SeedBackup,
    mask_state: bool,
    output_color: Color,
) -> Vec<Line<'static>> {
    let out_color = convert_color(output_color);
    let mask = |s: &str| if mask_state { "*".repeat(s.len()) } else { s.to_string() };

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("Seed Phrase: "),
        Span::styled(mask(&backup.seed_phrase), Style::default().fg(out_color)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("Passphrase: "),
        Span::styled(mask(&backup.passphrase), Style::default().fg(out_color)),
    ]));
    lines.push(Line::from(""));
    if !backup.sskr.groups.is_empty() {
        lines.push(Line::from("SSKR Backup:"));
        for (group_index, group_shares) in backup.sskr.groups.iter().enumerate() {
            lines.push(Line::from(format!("Group {} Shares:", group_index + 1)));
            for (share_index, share) in group_shares.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::raw(format!("  Share {}: Hex: ", share_index + 1)),
                    Span::styled(mask(&share.share_hex), Style::default().fg(out_color)),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("           Mnemonic: "),
                    Span::styled(mask(&share.mnemonic), Style::default().fg(out_color)),
                ]));
            }
        }
    }
    if !backup.recovery_info.is_empty() && !backup.sskr.groups.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(backup.recovery_info.clone()));
        lines.push(Line::from(""));
    }    
    lines.push(Line::from(vec![
        Span::raw("Entropy: "),
        Span::styled(mask(&backup.entropy), Style::default().fg(out_color)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("BIP-39 Seed: "),
        Span::styled(mask(&backup.bip39_seed), Style::default().fg(out_color)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("BIP-32 Root Key (xprv): "),
        Span::styled(mask(&backup.bip32_root_key), Style::default().fg(out_color)),
    ]));
    lines
}

fn run_address_table_ui(address_entries: Vec<AddressEntry>, addr_type: u8, theme_colors: &ThemeColors) -> Result<bool, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut mask_state = true;
    let mut selected_row: usize = 0;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(90), Constraint::Percentage(10)].as_ref())
                .split(f.area());
            let rows = address_entries.iter().enumerate().map(|(i, entry)| {
                let priv_display = if mask_state { "*".repeat(entry.privkey.len()) } else { entry.privkey.clone() };
                let row = TuiRow::new(vec![
                    entry.index.to_string(),
                    entry.address.clone(),
                    entry.pubkey.clone(),
                    priv_display,
                ]);
                if i == selected_row {
                    row.style(Style::default().bg(convert_color(theme_colors.highlighted)))
                } else {
                    row
                }
            });
            let table = TuiTable::new(rows, vec![
                    Constraint::Percentage(5),
                    Constraint::Percentage(25),
                    Constraint::Percentage(35),
                    Constraint::Percentage(35),
                ])
                .header(TuiRow::new(vec!["Index", "Address", "Public Key", "Private Key"])
                    .bottom_margin(1))
                .block(Block::default()
                    .borders(Borders::ALL)
                    .title(match addr_type {
                        1 => "Derived Bitcoin Addresses",
                        2 => "Derived Ethereum Addresses",
                        3 => "Derived XRP Addresses",
                        4 => "Derived Solana Addresses",
                        _ => "Derived Addresses",
                    }));
            f.render_widget(table, chunks[0]);
            let note = Paragraph::new("Use arrow keys to navigate, [Tab] to toggle private key visibility, [Enter] to show QR code, [r] to return, [q] to exit.")
                .style(Style::default().fg(TuiColor::White));
            f.render_widget(note, chunks[1]);
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Tab => mask_state = !mask_state,
                    KeyCode::Char('r') => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        return Ok(true);
                    },
                    KeyCode::Char('q') => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        return Ok(false);
                    },
                    KeyCode::Up => {
                        if selected_row > 0 {
                            selected_row -= 1;
                        }
                    },
                    KeyCode::Down => {
                        if selected_row < address_entries.len() - 1 {
                            selected_row += 1;
                        }
                    },
                    KeyCode::Enter => {
                        show_qr_popup(&address_entries[selected_row].privkey)?;
                        terminal.draw(|_f| {})?;
                    },
                    _ => {}
                }
            }
        }
    }
}

fn show_qr_popup(data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code.render::<Luma<u8>>()
                    .min_dimensions(38, 38)
                    .build();
    
    let temp_file = "qr_temp.png";
    image.save(temp_file)?;
    
    let (term_width, term_height) = if let Some((Width(w), Height(h))) = terminal_size::terminal_size() {
        (w, h)
    } else {
        (80, 24)
    };
    let center_x = (term_width.saturating_sub(38)) / 2;
    let center_y = (term_height.saturating_sub(38)) / 2;
    
    let config = viuer::Config {
        width: Some(38),
        height: Some(38),
        x: center_x as u16,
        y: center_y as i16,
        transparent: true,
        ..Default::default()
    };
    
    let mut stdout = io::stdout();
    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;
    viuer::print_from_file(temp_file, &config)?;
    
    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Esc {
                    break;
                }
            }
        }
    }
    
    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;
    
    std::fs::remove_file(temp_file)?;
    Ok(())
}

fn get_manual_seed(theme_colors: &ThemeColors) -> (bip39::Mnemonic, Vec<u8>) {
    loop {
        let input_value = prompt_user_input(
            "\nEnter your entropy (hex encoded) or seed phrase (BIP-39 mnemonic): ",
            theme_colors.input_prompt,
        );
        let trimmed_input = input_value.trim();
        let passphrase_input = prompt_user_input(
            "\nEnter your optional passphrase (leave blank for none): ",
            theme_colors.input_prompt,
        );

        if trimmed_input.contains(' ') {
            match validate_mnemonic(trimmed_input, bip39::Language::English) {
                Ok(()) => {
                    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, trimmed_input)
                        .expect("Valid mnemonic");
                    let seed = mnemonic.to_seed(&passphrase_input).to_vec();
                    return (mnemonic, seed);
                },
                Err(e) => {
                    let mut stdout = io::stdout();
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("{}", e);
                    stdout.execute(ResetColor).unwrap();
                    continue;
                }
            }
        } else {
            match hex::decode(trimmed_input) {
                Ok(entropy_bytes) => {
                    if ![16, 20, 24, 28, 32].contains(&entropy_bytes.len()) {
                        let mut stdout = io::stdout();
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Invalid entropy length. Expected 128, 160, 192, 224, or 256 bits. Please try again.");
                        stdout.execute(ResetColor).unwrap();
                        continue;
                    }
                    match bip39::Mnemonic::from_entropy(&entropy_bytes) {
                        Ok(mnemonic) => {
                            let seed = mnemonic.to_seed(&passphrase_input).to_vec();
                            return (mnemonic, seed);
                        },
                        Err(e) => {
                            let mut stdout = io::stdout();
                            stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                            println!("Failed to create mnemonic from entropy: {}. Please try again.", e);
                            stdout.execute(ResetColor).unwrap();
                            continue;
                        }
                    }
                },
                Err(e) => {
                    let mut stdout = io::stdout();
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("Hex decode error: {}. Please try again.", e);
                    stdout.execute(ResetColor).unwrap();
                    continue;
                }
            }
        }
    }
}

// Main Function
fn main() {
    let mut stdout = io::stdout();
    print!("\x1B[3J");
    stdout.execute(Clear(ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    stdout.flush().unwrap();

    let theme_colors = get_catppuccin_mocha_theme();

    stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
    println!("BIP-39 Tool");
    stdout.execute(ResetColor).unwrap();
    println!("
    \x1b[37mThis tool offers several functionalities for managing your cryptocurrency seed:
    1: Generate a new seed.
    2: Recover an existing seed from SSKR shares.
    3: Derive wallet addresses from a provided BIP-32 Extended Private Key (xprv).
    4: Decrypt and read a saved encrypted JSON backup.\x1b[0m

    \x1b[1;37mSeed Phrase Language Support:\x1b[0m
    \x1b[37m- This tool supports BIP-39 seed phrases in multiple languages, including English, French, Spanish, Italian, Japanese, Chinese (Simplified and Traditional), and more.
    - When selecting a language, the wordlist for seed phrase generation and validation will be based on that language.
    - The language setting does not translate words between different languages; it simply ensures that generated seed words conform to the selected wordlist.
    - If recovering an existing seed, ensure you select the correct language to match the original wordlist.\x1b[0m

    \x1b[1;37mSSKR (Sharded Secret Key Recovery):\x1b[0m
    \x1b[37m- SSKR splits your secret (seed) into multiple shares for enhanced security.
    - These shares can be distributed to different locations or entrusted to different parties.
    - To recover your seed, simply enter the required SSKR shares when prompted.
    - The program validates each share and securely reconstructs your original seed.\x1b[0m

    \x1b[1;37mStandard & Fully Hardened Address Generation:\x1b[0m
    \x1b[37m  - The tool supports generating addresses with both **standard** and **fully hardened** derivation paths.\x1b[0m

    \x1b[37m    Standard Derivation (m/Purpose'/CoinType'/Account'/ChainIndex):\x1b[0m
    \x1b[37m        - The first three levels (`Purpose'`, `CoinType'`, `Account'`) are \x1b[4;32mhardened\x1b[24m\x1b[37m, but the final `ChainIndex` is \x1b[4;32mnon-hardened\x1b[24m\x1b[37m.
     \x1b[37m       - Allows \x1b[4;32mpublic key derivation\x1b[24m\x1b[37m, meaning an extended public key (xpub) \x1b[4;32mcan\x1b[24m\x1b[37m be used to generate child public addresses.\x1b[0m\x1b[37m
    \x1b[37m        - This facilitates features like \x1b[4;32mwatch-only wallets\x1b[24m\x1b[37m, where public keys can be monitored without needing the private key.\x1b[0m
    \x1b[37m        - While convenient, they are slightly less secure since an exposed xpub could reveal multiple addresses, increasing risk if the xpub is leaked.\x1b[0m

    \x1b[37m    Fully Hardened Derivation (m/Purpose'/CoinType'/Account'/ChainIndex'\x1b[1;31;5m[!]\x1b[0m\x1b[37m):\x1b[0m
    \x1b[37m        - \x1b[4;32mEvery level is hardened\x1b[24m\x1b[37m, including the final `ChainIndex'`, preventing public key derivation beyond this point.\x1b[0m
    \x1b[37m        - Even if an extended public key (xpub) is exposed, an attacker \x1b[4;32mcannot\x1b[24m\x1b[37m derive sibling addresses or the parent private key.\x1b[0m
    \x1b[37m        - Provides \x1b[4;32man extra layer of security\x1b[24m\x1b[37m, as child keys are completely isolated from their parent structure.\x1b[0m

    \x1b[1;37mSeed Backup & JSON Encryption:\x1b[0m
    \x1b[37m- The JSON backup is encrypted to secure your seed data.
    - When entering your seed phrase, you can input one or multiple words separated by spaces.
    - Each word is automatically validated; once a valid word is entered, the prompt will advance to the next.
    - For a complete 24-word seed, the final (24th) word is computed automatically based on the required checksum.\x1b[0m

    ");
    enable_raw_mode().unwrap();
    await_key(30, &theme_colors);
    disable_raw_mode().unwrap();

    stdout.execute(Clear(ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();

    stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
    println!("Select an option:");
    stdout.execute(ResetColor).unwrap();
    println!("  1: Generate a new seed");
    println!("  2: Recover an existing seed from SSKR shares");
    println!("  3: Derive wallet addresses from entropy or seed phrase");
    println!("  4: Decrypt and read a saved encrypted JSON backup");

    let seed_option = loop {
        let input = prompt_user_input("Enter your selection (1-4): ", theme_colors.input_prompt);
        match input.parse::<u8>() {
            Ok(1) | Ok(2) | Ok(3) | Ok(4) => break input.parse::<u8>().unwrap(),
            _ => {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("Invalid selection. Please enter 1, 2, 3, or 4.");
                stdout.execute(ResetColor).unwrap();
            }
        }
    };

    if seed_option == 4 {
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        let file_path = "seed_backup.json.enc";
        let file_path = if Path::new(file_path).exists() {
            stdout.execute(Clear(ClearType::All)).unwrap();
            stdout.execute(cursor::MoveTo(0, 0)).unwrap();
            println!();
            stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
            println!("Found backup file: {}", file_path);
            stdout.execute(ResetColor).unwrap();
            file_path.to_string()
        } else {
            prompt_user_input(
                "\nEnter the full path to the encrypted JSON file (e.g., /path/to/seed_backup.json.enc): ",
                theme_colors.input_prompt,
            )
        };

        let mut file = match File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("Error opening file {}: {}", file_path, e);
                stdout.execute(ResetColor).unwrap();
                return;
            }
        };

        let mut encrypted_data = Vec::new();
        if let Err(e) = file.read_to_end(&mut encrypted_data) {
            stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
            println!("Error reading file {}: {}", file_path, e);
            stdout.execute(ResetColor).unwrap();
            return;
        }
        
        loop {
            let decryption_password = hidden_input(
                "\nEnter the decryption password: ",
                theme_colors.input_prompt,
            );

            match decrypt_data(&encrypted_data, &decryption_password) {
                Ok(decrypted_json) => {
                    match serde_json::from_str::<SeedBackup>(&decrypted_json) {
                        Ok(backup) => {
                            if let Err(e) = run_backup_text_ui(backup, theme_colors.clone(), "Decrypted Seed Backup ", false) {
                                eprintln!("Error in UI: {}", e);
                            }
                            break;
                        },
                        Err(e) => {
                            stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                            println!("Error parsing JSON: {}", e);
                            stdout.execute(ResetColor).unwrap();
                        }
                    }
                },
                Err(e) => {
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("Decryption failed: {}", e);
                    stdout.execute(ResetColor).unwrap();
                }
            }
            let try_again = prompt_single_key("Try again? (y/n): ", theme_colors.input_prompt);
            if try_again.to_ascii_lowercase() != 'y' {
                break;
            }
        }
        
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        return;
    }

    if seed_option == 3 {
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        println!();
        stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
        println!("You have chosen to derive wallet addresses from entropy or seed phrase.");
        stdout.execute(ResetColor).unwrap();

        let (mnemonic, seed) = if Path::new("seed_backup.json.enc").exists() {
            let backup_choice = prompt_single_key(
                "A backup file 'seed_backup.json.enc' was detected.\nPress [d] to decrypt it for address derivation, or any other key to enter manually: ",
                theme_colors.input_prompt,
            );
            if backup_choice.to_ascii_lowercase() == 'd' {
                let mut file = File::open("seed_backup.json.enc").expect("Could not open backup file");
                let mut encrypted_data = Vec::new();
                file.read_to_end(&mut encrypted_data).expect("Error reading backup file");
                let decryption_password = hidden_input(
                    "\nEnter the decryption password: ",
                    theme_colors.input_prompt,
                );
                match decrypt_data(&encrypted_data, &decryption_password) {
                    Ok(decrypted_json) => {
                        match serde_json::from_str::<SeedBackup>(&decrypted_json) {
                            Ok(backup) => {
                                stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
                                println!("\nBackup successfully decrypted.");
                                stdout.execute(ResetColor).unwrap();
                                let seed_bytes = hex::decode(&backup.bip39_seed)
                                    .expect("Failed to decode backup seed")
                                    .to_vec();
                                (bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &backup.seed_phrase)
                                    .expect("Failed to parse mnemonic"), seed_bytes)
                            },
                            Err(e) => {
                                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                                println!("Error parsing backup JSON: {}. Falling back to manual entry.", e);
                                stdout.execute(ResetColor).unwrap();
                                get_manual_seed(&theme_colors)
                            }
                        }
                    },
                    Err(e) => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Decryption failed: {}. Falling back to manual entry.", e);
                        stdout.execute(ResetColor).unwrap();
                        get_manual_seed(&theme_colors)
                    }
                }                
            } else {
                get_manual_seed(&theme_colors)
            }
        } else {
            get_manual_seed(&theme_colors)
        };

        let _mnemonic_phrase = mnemonic.to_string();
        let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)
            .expect("Unable to create master key");

        loop {
            stdout.execute(Clear(ClearType::All)).unwrap();
            stdout.execute(cursor::MoveTo(0, 0)).unwrap();
            stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
            println!("Select address type:");
            stdout.execute(ResetColor).unwrap();
            print!("  1: Bitcoin ");
            stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
            println!("(Native SegWit P2WPKH - m/84'/0'/0'/0/i)");
            stdout.execute(ResetColor).unwrap();
            print!("  2: Ethereum/EVM ");
            stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
            println!("(BIP-44 - m/44'/60'/0'/0/i)");
            stdout.execute(ResetColor).unwrap();
            print!("  3: XRP ");
            stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
            println!("(BIP-44 - m/44'/144'/0'/0/i)");
            stdout.execute(ResetColor).unwrap();
            print!("  4: Solana ");
            stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
            println!("(BIP-44 - m/44'/501'/0'/0')");
            stdout.execute(ResetColor).unwrap();

            let addr_type = loop {
                let input = prompt_user_input("\nEnter your selection (1-4): ", theme_colors.input_prompt);
                match input.parse::<u8>() {
                    Ok(1) | Ok(2) | Ok(3) | Ok(4) => break input.parse::<u8>().unwrap(),
                    _ => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Invalid selection. Please enter 1, 2, 3, or 4.");
                        stdout.execute(ResetColor).unwrap();
                    }
                }
            };

            let use_hardened_index = if addr_type == 1 || addr_type == 2 {
                stdout.execute(Clear(ClearType::All)).unwrap();
                stdout.execute(cursor::MoveTo(0, 0)).unwrap();
                println!("\nSelect derivation index type for the final component:");
                print!("  1: Fully Hardened Derivation ");
                stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
                print!("(e.g., i') ");
                stdout.execute(ResetColor).unwrap();
                print!("\x1b[1;31;5m[!]\x1b[0m");
                println!();
                print!("  2: Standard Derivation ");
                stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
                println!("(e.g., i)");
                stdout.execute(ResetColor).unwrap();
                let index_choice = loop {
                    let input = prompt_user_input("\nEnter your selection (1 or 2): ", theme_colors.input_prompt);
                    match input.parse::<u8>() {
                        Ok(1) | Ok(2) => break input.parse::<u8>().unwrap(),
                        _ => {
                            stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                            println!("Invalid selection. Please enter 1 or 2.");
                            stdout.execute(ResetColor).unwrap();
                        }
                    }
                };
                index_choice == 1
            } else if addr_type == 3 {
                false
            } else {
                true
            };

            let range_input = prompt_user_input("\nEnter address index range (e.g., 5-100): ", theme_colors.input_prompt);
            let parts: Vec<&str> = range_input.trim().split('-').collect();
            if parts.len() != 2 {
                println!("Invalid input format. Please use the format start-end (e.g., 5-100).");
                continue;
            }
            let start_index = parts[0].trim().parse::<u32>().expect("Invalid start index");
            let end_index = parts[1].trim().parse::<u32>().expect("Invalid end index");
            if start_index > end_index {
                println!("Start index cannot be greater than end index.");
                continue;
            }
            
            let secp = Secp256k1::new();
            let mut address_entries = Vec::new();

            match addr_type {
                1 => {
                    for i in start_index..=end_index {
                        let path_str = if use_hardened_index {
                            format!("m/84'/0'/0'/0/{}'", i)
                        } else {
                            format!("m/84'/0'/0'/0/{}", i)
                        };
                        let path = path_str.parse::<DerivationPath>()
                            .expect("Invalid derivation path");
                        let child_xprv = master_xprv.derive_priv(&secp, &path)
                            .expect("Derivation failed");
                        let child_pubkey_secp = PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                        let child_bitcoin_pubkey = bitcoin::PublicKey {
                            compressed: true,
                            inner: child_pubkey_secp,
                        };
                        let comp_pubkey = bitcoin::key::CompressedPublicKey::from_slice(&child_bitcoin_pubkey.to_bytes())
                            .expect("Failed to create compressed public key");
                        let addr_btc = Address::p2wpkh(&comp_pubkey, Network::Bitcoin);
                        let pubkey_hex = hex::encode(child_pubkey_secp.serialize());
                        let privkey_hex = hex::encode(child_xprv.private_key.secret_bytes());
                        address_entries.push(AddressEntry {
                            index: i,
                            address: addr_btc.to_string(),
                            pubkey: pubkey_hex,
                            privkey: privkey_hex,
                        });
                    }
                },
                2 => {
                    for i in start_index..=end_index {
                        let path_str = if use_hardened_index {
                            format!("m/44'/60'/0'/0/{}'", i)
                        } else {
                            format!("m/44'/60'/0'/0/{}", i)
                        };
                        let path = path_str.parse::<DerivationPath>()
                            .expect("Invalid derivation path");
                        let child_xprv = master_xprv.derive_priv(&secp, &path)
                            .expect("Derivation failed");
                        let child_pubkey = PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                        let eth_address = ethereum_address_from_pubkey(&child_pubkey);
                        let pubkey_hex = hex::encode(child_pubkey.serialize());
                        let privkey_hex = hex::encode(child_xprv.private_key.secret_bytes());
                        address_entries.push(AddressEntry {
                            index: i,
                            address: eth_address,
                            pubkey: pubkey_hex,
                            privkey: privkey_hex,
                        });
                    }
                },
                3 => {
                    for i in start_index..=end_index {
                        let path_str = if use_hardened_index {
                            format!("m/44'/144'/0'/0/{}'", i)
                        } else {
                            format!("m/44'/144'/0'/0/{}", i)
                        };
                        let path = path_str.parse::<DerivationPath>()
                            .expect("Invalid derivation path");
                        let child_xprv = master_xprv.derive_priv(&secp, &path)
                            .expect("Derivation failed");
                        let child_pubkey = PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                        let xrp_addr = xrp_address_from_pubkey(&child_pubkey);
                        let pubkey_hex = hex::encode(child_pubkey.serialize());
                        let privkey_hex = hex::encode(child_xprv.private_key.secret_bytes());
                        address_entries.push(AddressEntry {
                            index: i,
                            address: xrp_addr,
                            pubkey: pubkey_hex,
                            privkey: privkey_hex,
                        });
                    }
                },
                4 => {
                    for i in start_index..=end_index {
                        let path_str = format!("m/44'/501'/0'/0'/{}'", i);
                        let path = path_str.parse::<BIP32Path>()
                            .expect("Failed to parse BIP32 path for Solana");
                        let derived = derive_key_from_path(&seed, Curve::Ed25519, &path)
                            .expect("Failed to derive ed25519 key for Solana");
                    
                        let signing_key = SigningKey::from_bytes(&derived.key);
                        let verifying_key = VerifyingKey::from(&signing_key);
                    
                        let sol_address = bs58::encode(verifying_key.to_bytes()).into_string();
                        let pubkey_hex = hex::encode(verifying_key.to_bytes());
                        let privkey_hex = hex::encode(signing_key.to_bytes());
                    
                        address_entries.push(AddressEntry {
                            index: i,
                            address: sol_address,
                            pubkey: pubkey_hex,
                            privkey: privkey_hex,
                        });
                    }
                },
                _ => {
                    println!("Address type not supported!");
                }
            }
            
            let return_to_menu = run_address_table_ui(address_entries, addr_type, &theme_colors)
                .expect("Error running address table UI");
            if !return_to_menu {
                stdout.execute(Clear(ClearType::All)).unwrap();
                stdout.execute(cursor::MoveTo(0, 0)).unwrap();
                std::process::exit(0);
            }
        }
    }

    if seed_option == 2 {
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        println!();
        stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
        println!("You have chosen to recover an existing seed from SSKR shares.");
        stdout.execute(ResetColor).unwrap();
        
        println!("Enter SSKR shares in either ");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        print!("hexadecimal");
        stdout.execute(ResetColor).unwrap();
        print!(" or ");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        println!("mnemonic form.");
        stdout.execute(ResetColor).unwrap();
        
        println!("The system will automatically detect the input format and combine shares when enough valid ones are provided.");
        
        print!("Do not enter duplicate shares. ");
        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
        print!("\x1b[1;31;5m[!]\x1b[0m");
        stdout.execute(ResetColor).unwrap();
        println!();
        
        let mut all_shares: Vec<Vec<u8>> = Vec::new();
        loop {
            let input = prompt_user_input("\nEnter share (hex or mnemonic): ", theme_colors.input_prompt);
            if input.trim().is_empty() {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("Empty input; please enter a valid share.");
                stdout.execute(ResetColor).unwrap();
                continue;
            }
            let share_bytes = if input.contains(' ') {
                match mnemonic_to_share(&input, language_from_choice(1)) {
                    Some(bytes) => bytes,
                    None => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Invalid mnemonic share input.");
                        stdout.execute(ResetColor).unwrap();
                        continue;
                    }
                }
            } else {
                match hex::decode(&input) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Error decoding hex: {}", e);
                        stdout.execute(ResetColor).unwrap();
                        continue;
                    }
                }
            };
            if all_shares.contains(&share_bytes) {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("Duplicate share detected; please enter a new share.");
                stdout.execute(ResetColor).unwrap();
                continue;
            }
            all_shares.push(share_bytes);
            match sskr_combine(&all_shares) {
                Ok(secret) => {
                    println!("\nSufficient shares provided. Secret successfully recovered.");
                    let entropy = secret.as_ref().to_vec();
                    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
                        .expect("Failed to create mnemonic");
                    let passphrase = prompt_user_input("\nEnter an optional passphrase for seed derivation (leave blank to skip): ", theme_colors.input_prompt);
                    let seed = mnemonic.to_seed(&passphrase);
                    let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)
                        .expect("Unable to create master key");

                    let backup = SeedBackup {
                        seed_phrase: mnemonic.to_string(),
                        passphrase: passphrase,
                        sskr: SskrBackup { groups: vec![] },
                        entropy: hex::encode(&entropy),
                        bip39_seed: hex::encode(&seed),
                        bip32_root_key: format!("{}", master_xprv),
                        recovery_info: String::from("Recovered via SSKR shares"),
                    };

                    if let Err(e) = run_backup_text_ui(backup, theme_colors.clone(), "SSKR Shares Recovery", false) {
                        eprintln!("Error in UI: {}", e);
                    }
                    stdout.execute(Clear(ClearType::All)).unwrap();
                    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
                    return;
                },
                Err(_) => {
                    println!("Not enough valid shares yet. Please enter another share.");
                }
            }
        }
    } else {
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
        println!("\nSelect language:");
        stdout.execute(ResetColor).unwrap();
        println!("  1: English");
        println!("  2: Simplified Chinese");
        println!("  3: Traditional Chinese");
        println!("  4: Japanese");
        println!("  5: Korean");
        println!("  6: Spanish");
        println!("  7: French");
        println!("  8: Italian");
        println!("  9: Czech");
        println!(" 10: Portuguese");
        let language_choice = loop {
            let input = prompt_user_input("Enter your selection (1-10): ", theme_colors.input_prompt);
            match input.parse::<u8>() {
                Ok(num) if num >= 1 && num <= 10 => break num,
                _ => {
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("Invalid selection. Please enter a number between 1 and 10.");
                    stdout.execute(ResetColor).unwrap();
                }
            }
        };
        let language = language_from_choice(language_choice);
        let wordlist = language.word_list();
        let total_user_defined_positions = 23;
        let mut selected_indices: Vec<u16> = Vec::new();
        let mut rng = OsRng;
        let mut error_message: Option<String> = None;
        while selected_indices.len() < total_user_defined_positions {
            let current_position = selected_indices.len() + 1;
            stdout.execute(Clear(ClearType::All)).unwrap();
            stdout.execute(cursor::MoveTo(0, 0)).unwrap();
            stdout.execute(SetForegroundColor(theme_colors.header)).unwrap();
            println!("BIP-39 Tool");
            stdout.execute(ResetColor).unwrap();
            stdout.execute(SetForegroundColor(theme_colors.position_label)).unwrap();
            println!("Position {} of {}:", current_position, total_user_defined_positions);
            stdout.execute(ResetColor).unwrap();
            if !selected_indices.is_empty() {
                print!("Selected words so far: ");
                for &index in &selected_indices {
                    print!("{} ", wordlist[index as usize]);
                }
                println!();
            }
            if let Some(ref msg) = error_message {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("{}", msg);
                stdout.execute(ResetColor).unwrap();
            }
            println!();
            let input = prompt_user_input("Enter your desired mnemonic word(s) for this position (or press Enter for a random unused word): ", theme_colors.input_prompt);
            if input.is_empty() {
                let available: Vec<u16> = (0..wordlist.len() as u16)
                    .filter(|i| !selected_indices.contains(i))
                    .collect();
                if available.is_empty() {
                    error_message = Some("No available words remaining!".to_string());
                    continue;
                }
                let random_index = *available.choose(&mut rng).unwrap();
                stdout.execute(SetForegroundColor(theme_colors.random_message)).unwrap();
                println!("No input provided. Selecting a random word: {}", wordlist[random_index as usize]);
                stdout.execute(ResetColor).unwrap();
                selected_indices.push(random_index);
                error_message = None;
            } else {
                let mut tokens: Vec<&str> = input.split_whitespace().collect();
                let remaining_positions = total_user_defined_positions - selected_indices.len();
                if tokens.len() > remaining_positions {
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("More words were entered than required; only the first {} word(s) will be used.", remaining_positions);
                    stdout.execute(ResetColor).unwrap();
                    tokens.truncate(remaining_positions);
                }
                let mut is_valid = true;
                let mut indices_to_add = Vec::new();
                for token in tokens.iter() {
                    match wordlist.iter().position(|&w| w == *token) {
                        Some(idx) => {
                            if selected_indices.contains(&(idx as u16)) || indices_to_add.contains(&(idx as u16)) {
                                error_message = Some(format!("Error: The word '{}' has already been used.", token));
                                is_valid = false;
                                break;
                            }
                            indices_to_add.push(idx as u16);
                        },
                        None => {
                            error_message = Some(format!("Error: The word '{}' is not found in the BIP-39 wordlist.", token));
                            is_valid = false;
                            break;
                        }
                    }
                }
                if !is_valid {
                    continue;
                }
                selected_indices.extend(indices_to_add);
                error_message = None;
            }
        }
        print_dashed_line();
        println!("All 23 words have been finalized, representing {} bits of entropy.", selected_indices.len() * 11);
        let fixed_bits: Vec<bool> = selected_indices
            .iter()
            .flat_map(|&index| bits_from_u16(index, 11))
            .collect();
        let mut final_word_candidates = Vec::new();
        for candidate in 0..8 {
            let candidate_bits = bits_from_u16(candidate, 3);
            let mut entropy_bits = fixed_bits.clone();
            entropy_bits.extend(candidate_bits.clone());
            let entropy_bytes = bits_to_bytes(&entropy_bits);
            let hash = Sha256::digest(&entropy_bytes);
            let hash_byte = hash[0];
            let mut checksum_bits: Vec<bool> = Vec::with_capacity(8);
            for i in (0..8).rev() {
                checksum_bits.push(((hash_byte >> i) & 1) != 0);
            }            
            let mut final_word_bits = candidate_bits.clone();
            final_word_bits.extend(checksum_bits);
            let final_index = bits_to_u16(&final_word_bits);
            final_word_candidates.push(final_index);
        }
        stdout.execute(SetForegroundColor(theme_colors.candidate_header)).unwrap();
        println!();
        println!("Based on your input, the following candidate words have been computed for the final (24th) position:");
        stdout.execute(ResetColor).unwrap();
        for (i, &candidate_index) in final_word_candidates.iter().enumerate() {
            println!("  Option {}: {}", i + 1, wordlist[candidate_index as usize]);
        }
        let final_choice = loop {
            let input = prompt_user_input("Please select an option (1-8) for the final word: ", theme_colors.input_prompt);
            match input.parse::<usize>() {
                Ok(n) if n >= 1 && n <= final_word_candidates.len() => break n - 1,
                _ => {
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("Invalid selection. Enter a number between 1 and {}.", final_word_candidates.len());
                    stdout.execute(ResetColor).unwrap();
                }
            }
        };
        let final_word_index = final_word_candidates[final_choice];
        selected_indices.push(final_word_index);
        let mnemonic_words: Vec<&str> = selected_indices
            .iter()
            .map(|&idx| wordlist[idx as usize])
            .collect();
        let mnemonic_phrase = mnemonic_words.join(" ");
        stdout.execute(Clear(ClearType::All)).unwrap();
        stdout.execute(cursor::MoveTo(0, 0)).unwrap();
        println!("\nYour seed phrase is:");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        println!("{}", mnemonic_phrase);
        stdout.execute(ResetColor).unwrap();
        let _ = bip39::Mnemonic::parse_in_normalized(language, &mnemonic_phrase)
            .expect("Mnemonic validation unsuccessful");
        let recovered_entropy = bip39::Mnemonic::parse_in_normalized(language, &mnemonic_phrase)
            .expect("Failed to create mnemonic").to_entropy().to_vec();

        let passphrase = loop {
            let pass1 = hidden_input("\nEnter an optional passphrase for seed derivation (leave blank for none): ", theme_colors.input_prompt);
            let pass2 = hidden_input("Re-enter passphrase to confirm: ", theme_colors.input_prompt);
            if pass1 == pass2 {
                break pass1;
            } else {
                stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                println!("Passphrases do not match. Please try again.");
                stdout.execute(ResetColor).unwrap();
            }
        };

        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &mnemonic_phrase)
            .expect("Failed to parse mnemonic");
        let seed = mnemonic.to_seed(&passphrase);
        let master_xprv = Xpriv::new_master(Network::Bitcoin, &seed)
            .expect("Unable to create master key");
        println!();
        print!("Entropy: ");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        println!("{}", hex::encode(&recovered_entropy));
        stdout.execute(ResetColor).unwrap();
        print!("BIP-39 Seed: ");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        println!("{}", hex::encode(&seed));
        stdout.execute(ResetColor).unwrap();
        print!("BIP-32 Root Key (xprv): ");
        stdout.execute(SetForegroundColor(theme_colors.final_output)).unwrap();
        println!("{}", master_xprv);
        stdout.execute(ResetColor).unwrap();

        if seed_option == 1 {
            let backup_choice = prompt_user_input("\nWould you like to create an SSKR backup of your mnemonic entropy? (y/n): ", theme_colors.input_prompt);
            if backup_choice.trim().eq_ignore_ascii_case("y") {
                let secret = Secret::new(&recovered_entropy).unwrap();
                let num_groups = loop {
                    let input = prompt_user_input("Enter the number of backup groups: ", theme_colors.input_prompt);
                    if let Ok(n) = input.parse::<u8>() {
                        if n > 0 { break n; }
                    }
                    stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                    println!("Invalid entry. Please enter a positive number.");
                    stdout.execute(ResetColor).unwrap();
                };
                let mut group_specs = Vec::new();
                for group in 1..=num_groups {
                    println!("\nFor backup group {}:", group);
                    let total_shares = loop {
                        let input = prompt_user_input(&format!("Enter the total number of shares for group {}: ", group), theme_colors.input_prompt);
                        if let Ok(n) = input.parse::<u8>() {
                            if n > 0 { break n; }
                        }
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Please enter a valid positive number.");
                        stdout.execute(ResetColor).unwrap();
                    };
                    let required_shares = loop {
                        let input = prompt_user_input(&format!("Enter the number of shares required to recover group {}: ", group), theme_colors.input_prompt);
                        if let Ok(n) = input.parse::<u8>() {
                            if n > 0 && n <= total_shares { break n; }
                        }
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Please enter a valid number (must be >0 and ≤ total shares).");
                        stdout.execute(ResetColor).unwrap();
                    };
                    match GroupSpec::new(required_shares as usize, total_shares as usize) {
                        Ok(spec) => group_specs.push(spec),
                        Err(e) => {
                            stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                            println!("Error creating group spec: {:?}", e);
                            stdout.execute(ResetColor).unwrap();
                            return;
                        }
                    }
                }
                let quorum_threshold = if num_groups > 1 {
                    loop {
                        let input = prompt_user_input(&format!("Enter the number of groups required to recover the secret (1-{}): ", num_groups), theme_colors.input_prompt);
                        if let Ok(n) = input.parse::<u8>() {
                            if n >= 1 && n <= num_groups {
                                break n;
                            }
                        }
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Invalid entry. Please enter a number between 1 and {}.", num_groups);
                        stdout.execute(ResetColor).unwrap();
                    }
                } else {
                    1
                };
                let spec = match Spec::new(quorum_threshold as usize, group_specs) {
                    Ok(s) => s,
                    Err(e) => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Error creating SSKR spec: {:?}", e);
                        stdout.execute(ResetColor).unwrap();
                        return;
                    }
                };
                let shares: Vec<Vec<Vec<u8>>> = match sskr_generate(&spec, &secret) {
                    Ok(s) => s,
                    Err(e) => {
                        stdout.execute(SetForegroundColor(theme_colors.error)).unwrap();
                        println!("Error generating SSKR shares: {:?}", e);
                        stdout.execute(ResetColor).unwrap();
                        return;
                    }
                };
                let recovery_info = format!(
                    "In total, a minimum of {} out of {} group{} {} needed to recover your secret.",
                    quorum_threshold,
                    num_groups,
                    if num_groups == 1 { "" } else { "s" },
                    if quorum_threshold == 1 { "is" } else { "are" }
                );
                let mut sskr_backup: Vec<Vec<Share>> = Vec::new();
                for group_shares in shares.iter() {
                    let mut group_vec = Vec::new();
                    for share in group_shares.iter() {
                        let share_hex = hex::encode(share);
                        let mnemonic = share_to_mnemonic(share, bip39::Language::English);
                        group_vec.push(Share { share_hex, mnemonic });
                    }
                    sskr_backup.push(group_vec);
                }
                let backup = SeedBackup {
                    seed_phrase: mnemonic_phrase.to_string(),
                    passphrase: passphrase.to_string(),
                    sskr: SskrBackup { groups: sskr_backup },
                    entropy: hex::encode(&recovered_entropy),
                    bip39_seed: hex::encode(&seed),
                    bip32_root_key: format!("{}", master_xprv),
                    recovery_info,
                };

                if let Err(e) = run_backup_text_ui(backup, theme_colors.clone(), "SENSITIVE INFORMATION", true) {
                    eprintln!("Error in UI: {}", e);
                }
            } else {
                let backup = SeedBackup {
                    seed_phrase: mnemonic_phrase.to_string(),
                    passphrase: passphrase.to_string(),
                    sskr: SskrBackup { groups: vec![] },
                    entropy: hex::encode(&recovered_entropy),
                    bip39_seed: hex::encode(&seed),
                    bip32_root_key: format!("{}", master_xprv),
                    recovery_info: String::new(),
                };
                if let Err(e) = run_backup_text_ui(backup, theme_colors.clone(), "SENSITIVE INFORMATION", true) {
                    eprintln!("Error in UI: {}", e);
                }
            }
            stdout.execute(Clear(ClearType::All)).unwrap();
            stdout.execute(cursor::MoveTo(0, 0)).unwrap();
            return;
        }
    }
}

fn print_dashed_line() {
    if let Some((width, _)) = terminal_size::terminal_size() {
        println!("{}", "─".repeat(width.0 as usize));
    } else {
        println!("{}", "─".repeat(40));
    }
}
