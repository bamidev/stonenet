use std::cmp::max;

use compu::{encoder::BrotliOptions, DecodeError, DecodeStatus, EncodeStatus};

use crate::core::CompressionType;


pub fn compress(type_: CompressionType, data: &[u8]) -> Vec<u8> {
	debug_assert!(type_ != CompressionType::None);
	match type_ {
		CompressionType::Brotli => compress_brotli(data),
		CompressionType::None => Vec::new(),
	}
}

fn compress_brotli(input: &[u8]) -> Vec<u8> {
	let options = BrotliOptions::new().quality(11);
	let mut encoder = compu::encoder::Interface::brotli_rust(options);
	let mut output = Vec::with_capacity(max(input.len(), 1024));
	loop {
		let result = encoder.encode_vec(input, &mut output, compu::EncodeOp::Finish);
		match result.status {
			EncodeStatus::Continue => {}
			// Add 10% capacity if needed
			EncodeStatus::NeedOutput => output.reserve(max(input.len() / 10, 1024)),
			EncodeStatus::Error => panic!("encode error"),
			EncodeStatus::Finished => return output,
		}
	}
}

pub fn decompress(type_: CompressionType, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
	debug_assert!(type_ != CompressionType::None);
	match type_ {
		CompressionType::Brotli => decompress_brotli(data),
		CompressionType::None => Ok(Vec::new()),
	}
}

fn decompress_brotli(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
	let mut decoder = compu::decoder::Interface::brotli_rust();
	let mut output = Vec::with_capacity(input.len() * 2);
	loop {
		let result = decoder.decode_vec(input, &mut output).status?;
		match result {
			DecodeStatus::NeedInput => panic!("Not enough input, incomplete data?"),
			//If you need more output, please allocate spare capacity.
			//API never allocates, only you allocate
			DecodeStatus::NeedOutput => output.reserve(input.len() / 10),
			DecodeStatus::Finished => {
				return Ok(output);
			}
		}
	}
}

/// Tries to determine whether the file type uses compression already.
pub fn mime_type_use_compression(mime_type: &str) -> bool {
	if let Some(i) = mime_type.find('/') {
		let type_ = &mime_type[..i];
		let sub_type = &mime_type[(i + 1)..];

		match type_ {
			"application" => _mime_type_use_compression_application(&sub_type),
			"audio" => _mime_type_use_compression_audio(&sub_type),
			"image" => _mime_type_use_compression_image(&sub_type),
			"video" => false,
			_ => true,
		}
	} else {
		false
	}
}

fn _mime_type_use_compression_application(sub_type: &str) -> bool {
	let blacklist = ["gzip", "zip", "zlib", "zstd"];
	!blacklist.contains(&sub_type)
}

fn _mime_type_use_compression_audio(sub_type: &str) -> bool {
	let whitelist = ["wav"];
	!whitelist.contains(&sub_type)
}

fn _mime_type_use_compression_image(sub_type: &str) -> bool {
	let blacklist = ["apng", "jpeg", "gif", "png", "webp"];
	!blacklist.contains(&sub_type)
}
