#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <locale>
#include <vector>

#include <archive.h>
#include <archive_entry.h>

namespace {
  int copy_data(struct archive* read_archive, struct archive* write_archive) {
    void const* buffer = nullptr;
    size_t size = 0;
    int64_t offset = 0;

    auto data = std::vector< uint8_t >{};
    while (true) {
      auto read_result
        = archive_read_data_block(read_archive, &buffer, &size, &offset);
      if (read_result == ARCHIVE_EOF) break;
      if (read_result != ARCHIVE_OK)
        return std::cerr << archive_error_string(read_archive) << std::endl,
               assert(false), read_result;

      if (data.size() < offset + size) data.resize(offset + size);
      std::memcpy(&data[offset], buffer, size);
    }

    auto write_result
      = archive_write_data(write_archive, &data[0], data.size());
    if (write_result == -1 || write_result != data.size())
      return std::cerr << archive_error_string(write_archive) << std::endl,
             assert(false), write_result;
    return ARCHIVE_OK;
  }
}

int main(int argc, char const* argv[]) {
  std::locale::global(std::locale(""));

  auto write_format = std::string{};
  auto write_filter = std::string{};
  for (auto i = 1; i < argc - 2; ++i) {
    if (std::string{argv[i]} == "--format") write_format = argv[i + 1];
    if (std::string{argv[i]} == "--filter") write_filter = argv[i + 1];
  }
  auto read_filename = std::string{argv[argc - 2]};
  auto write_filename = std::string{argv[argc - 1]};

  auto read_archive = archive_read_new();
  if (read_archive == NULL)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;
  if (archive_read_support_filter_all(read_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;
  if (archive_read_support_format_all(read_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;
  if (archive_read_open_filename(read_archive, read_filename.c_str(), 10240)
      != ARCHIVE_OK)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;

  auto write_archive = archive_write_new();
  if (write_archive == NULL)
    return std::cerr << archive_error_string(write_archive) << std::endl,
           assert(false), -1;

  if (write_format.empty()) {
    auto ldot = write_filename.rfind('.');
    if (ldot == std::string::npos) return -1;
    auto write_extension = write_filename.substr(ldot);

    auto write_tarextension = std::string{};
    if (ldot > 4) {
      auto lldot = write_filename.rfind('.', ldot - 1);
      if (lldot != std::string::npos
          && write_filename.substr(lldot, ldot - lldot) == ".tar") {
        write_filter = write_extension;
        write_extension = ".tar";
      }
    }

    if (write_extension == ".7z" || write_extension == ".7zip"
        || write_extension == ".cb7")
      write_format = "7z";
    else if (write_extension == ".zip")
      write_format = "zip";
    else if (write_extension == ".cbz") {
      write_format = "zip";
      write_filter = "none";
    } else if (write_extension == ".tar")
      write_format = "tar" + write_filter;
    else if (write_extension == ".cbt")
      write_format = "tar";
  }

  if (write_format.substr(0, 2) == "7z") {
    if (archive_write_set_format_7zip(write_archive) != ARCHIVE_OK)
      return std::cerr << archive_error_string(write_archive) << std::endl,
             assert(false), -1;
  } else if (write_format.substr(0, 3) == "zip") {
    if (archive_write_set_format_zip(write_archive) != ARCHIVE_OK)
      return std::cerr << archive_error_string(write_archive) << std::endl,
             assert(false), -1;
    if (write_filter == "none") {
      if (archive_write_zip_set_compression_store(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    } else {
      if (archive_write_zip_set_compression_deflate(write_archive)
          != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    }
  } else if (write_format.substr(0, 3) == "tar") {
    if (write_filter == ".bz2") {
      if (archive_write_add_filter_bzip2(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    } else if (write_filter == ".gz") {
      if (archive_write_add_filter_gzip(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
      //    } else if (write_filter == ".lz4") {
      //      if (archive_write_add_filter_lz4(write_archive) != ARCHIVE_OK)
      //        return assert(false), std::cerr <<
      //        archive_error_string(write_archive) <<
      //        std::endl,
      //               -1;
    } else if (write_filter == ".lzma") {
      if (archive_write_add_filter_lzma(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    } else if (write_filter == ".lzo") {
      if (archive_write_add_filter_lzop(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    } else if (write_filter == ".xz") {
      if (archive_write_add_filter_xz(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    } else {
      if (archive_write_add_filter_none(write_archive) != ARCHIVE_OK)
        return std::cerr << archive_error_string(write_archive) << std::endl,
               assert(false), -1;
    }
    if (archive_write_set_format_gnutar(write_archive) != ARCHIVE_OK)
      return std::cerr << archive_error_string(write_archive) << std::endl,
             assert(false), -1;
  }
  // int archive_write_add_filter_b64encode(struct archive *);
  // int archive_write_add_filter_compress(struct archive *);
  // int archive_write_add_filter_grzip(struct archive *);
  // int archive_write_add_filter_lrzip(struct archive *);
  // int archive_write_add_filter_lzip(struct archive *);
  // int archive_write_add_filter_uuencode(struct archive *);

  // int archive_write_set_format_ar_bsd(struct archive *);
  // int archive_write_set_format_ar_svr4(struct archive *);
  // int archive_write_set_format_cpio(struct archive *);
  // int archive_write_set_format_cpio_newc(struct archive *);
  // int archive_write_set_format_iso9660(struct archive *);
  // int archive_write_set_format_mtree(struct archive *);
  // int archive_write_set_format_mtree_classic(struct archive *);
  // int archive_write_set_format_pax(struct archive *);
  // int archive_write_set_format_pax_restricted(struct archive *);
  // int archive_write_set_format_raw(struct archive *);
  // int archive_write_set_format_shar(struct archive *);
  // int archive_write_set_format_shar_dump(struct archive *);
  // int archive_write_set_format_ustar(struct archive *);
  // int archive_write_set_format_v7tar(struct archive *);
  // int archive_write_set_format_warc(struct archive *);
  // int archive_write_set_format_xar(struct archive *);

  if (archive_write_open_filename(write_archive, write_filename.c_str())
      != ARCHIVE_OK)
    return std::cerr << archive_error_string(write_archive) << std::endl,
           assert(false), -1;

  auto entry = archive_entry_new2(read_archive);
  while (true) {
    archive_entry_clear(entry);

    auto read_result = archive_read_next_header2(read_archive, entry);
    if (read_result == ARCHIVE_EOF)
      break;
    else if (read_result == ARCHIVE_WARN)
      std::cerr << "W: " << archive_error_string(read_archive) << std::endl;
    else if (read_result != ARCHIVE_OK)
      return std::cerr << archive_error_string(read_archive) << std::endl,
             assert(false), -1;
    // std::cout << "x " << archive_entry_pathname(entry) << std::endl;

    auto write_result = archive_write_header(write_archive, entry);
    if (write_result == ARCHIVE_WARN)
      std::cerr << "W: " << archive_error_string(read_archive) << std::endl;
    else if (write_result != ARCHIVE_OK)
      return std::cerr << archive_error_string(read_archive) << std::endl,
             assert(false), -1;

    if (copy_data(read_archive, write_archive) != ARCHIVE_OK)
      return std::cerr << archive_error_string(read_archive) << std::endl,
             assert(false), -1;
  }
  archive_entry_free(entry);

  if (archive_write_close(write_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(write_archive) << std::endl,
           assert(false), -1;
  if (archive_write_free(write_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(write_archive) << std::endl,
           assert(false), -1;

  if (archive_read_close(read_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;
  if (archive_read_free(read_archive) != ARCHIVE_OK)
    return std::cerr << archive_error_string(read_archive) << std::endl,
           assert(false), -1;

  return 0;
}
