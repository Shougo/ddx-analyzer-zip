import type { DdxBuffer } from "@shougo/ddx-vim/types";
import {
  type AnalyzeResult,
  type AnalyzeValueInteger,
  type AnalyzeValueString,
  BaseAnalyzer,
} from "@shougo/ddx-vim/analyzer";
import { arrayEquals, parseOneLine } from "@shougo/ddx-vim/utils";

export type Params = Record<string, never>;

type Signature = [number, number, number, number];

export class Analyzer extends BaseAnalyzer<Params> {
  override detect(args: {
    buffer: DdxBuffer;
  }): boolean {
    return arrayEquals(args.buffer.getBytes(0, 2), [0x50, 0x4b]);
  }

  override parse(args: {
    buffer: DdxBuffer;
  }): AnalyzeResult[] {
    const results: AnalyzeResult[] = [];
    let offset = 0;

    while (true) {
      const signature = Array.from(
        args.buffer.getBytes(offset, 4),
      ) as Signature;

      if (arrayEquals(signature, [0x50, 0x4b, 0x03, 0x04])) {
        const [, nextOffset] = this.analyzeZipHeader(
          args.buffer,
          results,
          offset,
        );
        offset = nextOffset;
      } else if (arrayEquals(signature, [0x50, 0x4b, 0x07, 0x08])) {
        const [, nextOffset] = this.analyzeZipHeader2(
          args.buffer,
          results,
          offset,
        );
        offset = nextOffset;
      } else if (arrayEquals(signature, [0x50, 0x4b, 0x01, 0x02])) {
        const [, nextOffset] = this.analyzeZipCentralHeader(
          args.buffer,
          results,
          offset,
        );
        offset = nextOffset;
      } else if (arrayEquals(signature, [0x50, 0x4b, 0x05, 0x06])) {
        const [, nextOffset] = this.analyzeZipEndHeader(
          args.buffer,
          results,
          offset,
        );
        offset = nextOffset;
      } else {
        break;
      }
    }

    return results;
  }

  override params(): Params {
    return {};
  }

  private parseSignature(
    buffer: DdxBuffer,
    header: AnalyzeResult,
    offset: number,
  ): number {
    for (let i = 0; i < 4; i++) {
      header.values.push({
        name: `signature${i}`,
        rawType: "integer",
        value: buffer.getInt8(offset),
        size: 1,
        address: offset,
      });
      offset += 1;
    }
    return offset;
  }

  private parseLine(
    buffer: DdxBuffer,
    header: AnalyzeResult,
    offset: number,
    line: string,
  ): [AnalyzeValueInteger | AnalyzeValueString, number] {
    const [value, nextOffset] = parseOneLine(line, buffer, offset);
    header.values.push(value);
    return [value, nextOffset];
  }

  private parseLineOffset(
    buffer: DdxBuffer,
    header: AnalyzeResult,
    offset: number,
    line: string,
  ): number {
    const [value, nextOffset] = parseOneLine(line, buffer, offset);
    header.values.push(value);
    return nextOffset;
  }

  private analyzeZipHeader(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "ZIP_HEADER", values: [] };

    offset = this.parseSignature(buffer, header, offset);

    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t version;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t flags;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t compression;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t dos_time;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t dos_date;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t crc32;",
    );

    let value;
    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint32_t compressed_size;",
    );
    const compressedSize = (value as AnalyzeValueInteger).value;

    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint32_t uncompressed_size;",
    );
    const uncompressedSize = (value as AnalyzeValueInteger).value;

    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint16_t file_name_length;",
    );
    const filenameLength = (value as AnalyzeValueInteger).value;

    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint16_t extra_field_length;",
    );
    const extraFieldLength = (value as AnalyzeValueInteger).value;

    const filename: AnalyzeValueString = {
      name: "filename",
      rawType: "string",
      value: buffer.getChars(offset, filenameLength),
      size: filenameLength,
      address: offset,
    };
    header.values.push(filename);
    offset += filenameLength;

    header.values.push({
      name: "extra field",
      rawType: "string",
      value: "?",
      address: offset,
    });
    offset += extraFieldLength;

    header.values.push({
      name: "data",
      rawType: "string",
      value: "?",
      address: offset,
    });

    // If compressed size is unknown/zero, do not blindly skip ahead.
    // Leave offset at the current position and continue parsing from there.
    if (compressedSize > 0) {
      offset += compressedSize;
    } else if (uncompressedSize > 0) {
      offset += uncompressedSize;
    }

    results.push(header);
    return [results, offset];
  }

  private analyzeZipHeader2(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "ZIP_HEADER(PK78)", values: [] };

    offset = this.parseSignature(buffer, header, offset);

    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t crc32;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t compressed_size;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t uncompressed_size;",
    );

    results.push(header);
    return [results, offset];
  }

  private analyzeZipCentralHeader(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "ZIP_CENTRAL_HEADER", values: [] };

    offset = this.parseSignature(buffer, header, offset);

    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t version_made;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t version;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t flags;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t compression;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t dos_time;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t dos_date;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t crc32;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t compressed_size;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t uncompressed_size;",
    );

    let value;
    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint16_t file_name_length;",
    );
    const filenameLength = (value as AnalyzeValueInteger).value;

    [value, offset] = this.parseLine(
      buffer,
      header,
      offset,
      "uint16_t extra_field_length;",
    );
    const extraFieldLength = (value as AnalyzeValueInteger).value;

    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t file_comment_length;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t disk_number_start;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t internal_file_attributes;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t external_file_attributes;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t position;",
    );

    const filename: AnalyzeValueString = {
      name: "filename",
      rawType: "string",
      value: buffer.getChars(offset, filenameLength),
      size: filenameLength,
      address: offset,
    };
    header.values.push(filename);
    offset += filenameLength;

    header.values.push({
      name: "extra field",
      rawType: "string",
      value: "?",
      address: offset,
    });
    offset += extraFieldLength;

    results.push(header);
    return [results, offset];
  }

  private analyzeZipEndHeader(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "ZIP_END_HEADER", values: [] };

    offset = this.parseSignature(buffer, header, offset);

    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t number_of_disks;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t disk_number_start;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t number_of_disk_entries;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t number_of_entries;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t central_dir_size;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t central_dir_offset;",
    );
    offset = this.parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t file_comment_length;",
    );

    results.push(header);
    return [results, offset];
  }
}
