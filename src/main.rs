use std::{
    fs::File,
    io::Read,
    time::{Duration, SystemTime},
};

use crossbeam::thread;
use solana_bpf_loader_program::{syscalls::register_syscalls, BpfError, ThisInstructionMeter};
use solana_client::{
    client_error::ClientError, rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig,
};
use solana_program_runtime::invoke_context::InvokeContext;
use solana_rbpf::{elf, verifier, vm};
use solana_sdk::{
    bpf_loader_upgradeable::{
        close, create_buffer, deploy_with_max_program_len, upgrade, write, UpgradeableLoaderState,
    },
    commitment_config::{CommitmentConfig, CommitmentLevel},
    hash::Hash,
    message::Message,
    packet::PACKET_DATA_SIZE,
    signature::{read_keypair_file, Keypair, Signature},
    signer::Signer,
    transaction::Transaction,
    transaction_context::TransactionContext,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value_t = dotenv::var("RPC_ENDPOINT").unwrap())]
    pub rpc_endpoint: String,

    #[clap(short, long, default_value_t = dotenv::var("TIMEOUT").unwrap())]
    timeout: String,

    #[clap(short, long, default_value_t = dotenv::var("MAX_RETRIES").unwrap())]
    max_retries: String,
    
    #[clap(short, long, default_value_t = dotenv::var("PAYER_KP_PATH").unwrap())]
    payer_kp_path: String,
    
    #[clap(short, long, default_value_t = dotenv::var("PROGRAM_KP_PATH").unwrap())]
    program_kp_path: String,
   
    #[clap(short, long, default_value_t = dotenv::var("PROGRAM_PATH").unwrap())]
    program_path: String,
    
    #[clap(short, long, default_value_t = dotenv::var("THREAD_COUNT").unwrap())]
    thread_count: String,
    
    #[clap(short, long, default_value_t = dotenv::var("SLEEP").unwrap())]
    sleep: String,
    
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args = Args::parse();

    let timeout_sec = args.timeout.parse::<u64>()?;
    let url = args.rpc_endpoint;
    let timeout = Duration::from_secs(timeout_sec);
    let commitment_config = CommitmentConfig::confirmed();
    let confirm_transaction_initial_timeout = Duration::from_secs(5);
    let send_config = RpcSendTransactionConfig {
        preflight_commitment: Some(CommitmentLevel::Confirmed),
        max_retries: Some(args.max_retries.parse::<usize>()?),
        ..Default::default()
    };

    let client = RpcClient::new_with_timeouts_and_commitment(
        url,
        timeout,
        commitment_config,
        confirm_transaction_initial_timeout,
    );

    // Payer
    let payer_kp =
        read_keypair_file(args.payer_kp_path).expect("Couldn't read payer keypair");
    let payer_pk = payer_kp.pubkey();

    println!("Payer: {}", payer_pk.to_string());

    // Program
    let program_kp =
        read_keypair_file(args.program_kp_path).expect("Couldn't read program keypair");
    let program_pk = program_kp.pubkey();

    let program_data =
        read_and_verify_elf(&dotenv::var("PROGRAM_PATH")?[..]).unwrap_or_else(|e| panic!("{e}"));
    let program_len = program_data.len();

    // Start timer
    let program_start_time = SystemTime::now();

    // Create buffer
    let buffer_kp = Keypair::new();
    let buffer_pk = buffer_kp.pubkey();
    let buffer_len = UpgradeableLoaderState::buffer_len(program_len)?;
    let buffer_lamports = client
        .get_minimum_balance_for_rent_exemption(buffer_len)
        .expect("Couldn't get balance for r.e");

    println!(
        "Need {} SOL to create buffer account",
        buffer_lamports as f64 / 1_000_000_000.
    );

    let payer_balance = client
        .get_balance(&payer_pk)
        .expect("Couldn't get payer balance");

    println!(
        "Current balance: {} SOL",
        payer_balance as f64 / 1_000_000_000.
    );

    if payer_balance < buffer_lamports {
        panic!("Not enough balance!");
    }

    let create_buffer_ix = create_buffer(
        &payer_pk,
        &buffer_pk,
        &payer_pk,
        buffer_lamports,
        program_len,
    )
    .expect("Couldn't create buffer ix");

    let mut recent_hash = client
        .get_latest_blockhash()
        .expect("Couldn't get recent blockhash");

    let create_buffer_tx = Transaction::new_signed_with_payer(
        &create_buffer_ix,
        Some(&payer_pk),
        &[&payer_kp, &buffer_kp],
        recent_hash,
    );

    let create_buffer_hash = client
        .send_and_confirm_transaction_with_spinner_and_config(
            &create_buffer_tx,
            commitment_config,
            send_config,
        )
        .expect("Create buffer tx error");

    // Write buffer
    // let recent_hash_clone = recent_hash.clone();

    let create_msg = |offset: u32, bytes: Vec<u8>, recent_hash: Hash| {
        let write_ix = write(&buffer_pk, &payer_pk, offset, bytes);

        Message::new_with_blockhash(&[write_ix], Some(&payer_pk), &recent_hash)
    };

    let chunk_size = calculate_max_chunk_size(&create_msg);
    let buffer_tx_count = buffer_len / chunk_size + 2;

    println!("Confirmed (1/{}): {}", buffer_tx_count, create_buffer_hash);

    let mut start_time = SystemTime::now();

    let payer_kp_ref = &payer_kp;
    let client = &client;

    let thread_count = args.thread_count
        .parse::<usize>()?;

    let close_buffer = |recent_hash: Hash| {
        let close_ix = close(&buffer_pk, &payer_pk, &payer_pk);

        let close_tx = Transaction::new_signed_with_payer(
            &[close_ix],
            Some(&payer_pk),
            &[&payer_kp],
            recent_hash,
        );

        client
            .send_and_confirm_transaction_with_spinner_and_config(
                &close_tx,
                commitment_config,
                send_config,
            )
            .expect("Unable to close the buffer");
    };

    for (i, threads_chunk) in program_data.chunks(chunk_size * thread_count).enumerate() {
        let current_time = SystemTime::now();
        let time_passed = current_time.duration_since(start_time)?.as_secs();
        if time_passed > 30 {
            recent_hash = client
                .get_latest_blockhash()
                .expect("Couldn't get recent blockhash");

            start_time = SystemTime::now();
        }

        // Spawn threads
        let result = thread::scope(move |s| {
            for j in 0..thread_count {
                let total_index = i * thread_count + j;

                s.spawn(move |_| {
                    let offset = (total_index * chunk_size) as u32;
                    if offset >= program_len as u32 {
                        return;
                    }

                    let chunks: Vec<&[u8]> = threads_chunk
                        .chunks(chunk_size)
                        .enumerate()
                        .filter(|(i, _)| i == &j)
                        .map(|(_, b)| b)
                        .collect();

                    let write_msg = create_msg(offset, chunks[0].to_vec(), recent_hash);

                    let write_tx = Transaction::new(&[payer_kp_ref], write_msg, recent_hash);

                    let write_hash = send_and_confirm_transaction_with_config(
                        &client,
                        &write_tx,
                        commitment_config,
                        send_config,
                        timeout_sec,
                    )
                    .expect("Write tx error");

                    println!(
                        "Confirmed ({}/{}): {}",
                        total_index + 2,
                        buffer_tx_count,
                        write_hash
                    );
                });
            }
        });

        if let Err(_) = result {
            close_buffer(recent_hash);
        }
    }

    // Deploy / upgrade
    let program_account = client.get_account(&program_pk);
    recent_hash = client
        .get_latest_blockhash()
        .expect("Couldn't get recent blockhash");

    let result;

    if let Err(_) = program_account {
        println!("Deploying {}", program_pk.to_string());

        let program_lamports = client
            .get_minimum_balance_for_rent_exemption(UpgradeableLoaderState::program_len().unwrap())
            .expect("Couldn't get balance for program");

        let deploy_ix = deploy_with_max_program_len(
            &payer_pk,
            &program_pk,
            &buffer_pk,
            &payer_pk,
            program_lamports,
            program_len * 2,
        )
        .expect("Couldn't create deploy ix");

        let deploy_tx = Transaction::new_signed_with_payer(
            &deploy_ix,
            Some(&payer_pk),
            &[&payer_kp, &program_kp],
            recent_hash,
        );

        result = client.send_and_confirm_transaction_with_spinner_and_config(
            &deploy_tx,
            commitment_config,
            send_config,
        )
    } else {
        println!("Upgrading {}", program_pk.to_string());

        let upgrade_ix = upgrade(&program_pk, &buffer_pk, &payer_pk, &payer_pk);

        let upgrade_tx = Transaction::new_signed_with_payer(
            &[upgrade_ix],
            Some(&payer_pk),
            &[&payer_kp],
            recent_hash,
        );

        result = client.send_and_confirm_transaction_with_spinner_and_config(
            &upgrade_tx,
            commitment_config,
            send_config,
        )
    }

    // Close buffer if it failed
    if let Err(_) = result {
        close_buffer(recent_hash);
    }

    let finish_time = SystemTime::now();
    let time_passed = finish_time.duration_since(program_start_time)?.as_secs();
    Ok(println!("✅ Success! Completed in {time_passed}s",))
}

fn calculate_max_chunk_size<F>(create_msg: &F) -> usize
where
    F: Fn(u32, Vec<u8>, Hash) -> Message,
{
    let baseline_msg = create_msg(0, Vec::new(), Hash::new_unique());
    let tx_size = bincode::serialized_size(&Transaction {
        signatures: vec![
            Signature::default();
            baseline_msg.header.num_required_signatures as usize
        ],
        message: baseline_msg,
    })
    .unwrap() as usize;
    // add 1 byte buffer to account for shortvec encoding
    PACKET_DATA_SIZE.saturating_sub(tx_size).saturating_sub(1)
}

fn read_and_verify_elf(program_location: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(program_location)
        .map_err(|err| format!("Unable to open program file: {}", err))?;
    let mut program_data = Vec::new();
    file.read_to_end(&mut program_data)
        .map_err(|err| format!("Unable to read program file: {}", err))?;
    let mut transaction_context = TransactionContext::new(Vec::new(), 1, 1);
    let mut invoke_context = InvokeContext::new_mock(&mut transaction_context, &[]);

    // Verify the program
    elf::Executable::<BpfError, ThisInstructionMeter>::from_elf(
        &program_data,
        Some(verifier::check),
        vm::Config {
            reject_broken_elfs: true,
            ..vm::Config::default()
        },
        register_syscalls(&mut invoke_context).unwrap(),
    )
    .map_err(|err| format!("ELF error: {}", err))?;

    Ok(program_data)
}

fn send_and_confirm_transaction_with_config(
    client: &RpcClient,
    transaction: &Transaction,
    commitment: CommitmentConfig,
    config: RpcSendTransactionConfig,
    timeout: u64,
) -> Result<Signature, ClientError> {
    let mut hash;

    'outer: loop {
        hash = client.send_transaction_with_config(transaction, config)?;

        let start_time = SystemTime::now();

        loop {
            if let Ok(resp) = client.confirm_transaction_with_commitment(&hash, commitment) {
                if resp.value {
                    break 'outer;
                }
            }

            let current_time = SystemTime::now();
            if current_time.duration_since(start_time).unwrap().as_secs() > timeout {
                break;
            }

            std::thread::sleep(Duration::from_millis(
                dotenv::var("SLEEP")
                    .unwrap_or(String::from("0"))
                    .parse::<u64>()
                    .unwrap(),
            ));
        }
    }

    Ok(hash)
}
