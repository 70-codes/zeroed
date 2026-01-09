//! Archive module for historical data storage
//!
//! This module provides functionality for archiving old data to disk,
//! organizing it by time periods for efficient retrieval and cleanup.

use crate::core::error::{Result, StorageError, ZeroedError};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Archive configuration
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Base directory for archives
    pub base_dir: PathBuf,
    /// Maximum age of archives in days (older archives are deleted)
    pub max_age_days: u32,
    /// Compression enabled
    pub compression: bool,
    /// Compression level (1-9)
    pub compression_level: u8,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("/var/lib/zeroed/archive"),
            max_age_days: 30,
            compression: true,
            compression_level: 6,
        }
    }
}

/// Archive manager for historical data
pub struct ArchiveManager {
    config: ArchiveConfig,
}

impl ArchiveManager {
    /// Create a new archive manager
    pub fn new(config: ArchiveConfig) -> Result<Self> {
        fs::create_dir_all(&config.base_dir).map_err(|e| {
            ZeroedError::Storage(StorageError::InitializationError {
                path: config.base_dir.clone(),
                message: e.to_string(),
            })
        })?;

        Ok(Self { config })
    }

    /// Get the directory path for a specific date
    pub fn get_date_dir(&self, date: NaiveDate) -> PathBuf {
        self.config
            .base_dir
            .join(date.format("%Y-%m-%d").to_string())
    }

    /// Get the file path for an hourly archive
    pub fn get_hourly_path(&self, date: NaiveDate, hour: u32) -> PathBuf {
        let dir = self.get_date_dir(date);
        let ext = if self.config.compression {
            "zbin"
        } else {
            "bin"
        };
        dir.join(format!("hour_{:02}.{}", hour, ext))
    }

    /// Archive data for a specific hour
    pub fn archive_hourly<T: Serialize>(
        &self,
        date: NaiveDate,
        hour: u32,
        data: &[T],
    ) -> Result<()> {
        let dir = self.get_date_dir(date);
        fs::create_dir_all(&dir).map_err(|e| {
            ZeroedError::Storage(StorageError::WriteError {
                message: e.to_string(),
            })
        })?;

        let path = self.get_hourly_path(date, hour);
        let file = File::create(&path).map_err(|e| {
            ZeroedError::Storage(StorageError::WriteError {
                message: e.to_string(),
            })
        })?;

        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, data).map_err(|e| {
            ZeroedError::Storage(StorageError::SerializationError {
                message: e.to_string(),
            })
        })?;

        info!("Archived {} records to {:?}", data.len(), path);
        Ok(())
    }

    /// Load archived data for a specific hour
    pub fn load_hourly<T: for<'de> Deserialize<'de>>(
        &self,
        date: NaiveDate,
        hour: u32,
    ) -> Result<Vec<T>> {
        let path = self.get_hourly_path(date, hour);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&path).map_err(|e| {
            ZeroedError::Storage(StorageError::ReadError {
                message: e.to_string(),
            })
        })?;

        let reader = BufReader::new(file);
        let data: Vec<T> = bincode::deserialize_from(reader).map_err(|e| {
            ZeroedError::Storage(StorageError::DeserializationError {
                message: e.to_string(),
            })
        })?;

        Ok(data)
    }

    /// Load all archived data for a specific date
    pub fn load_daily<T: for<'de> Deserialize<'de>>(&self, date: NaiveDate) -> Result<Vec<T>> {
        let mut all_data = Vec::new();

        for hour in 0..24 {
            let hourly = self.load_hourly::<T>(date, hour)?;
            all_data.extend(hourly);
        }

        Ok(all_data)
    }

    /// Clean up archives older than max_age_days
    pub fn cleanup(&self) -> Result<usize> {
        let cutoff =
            Utc::now().date_naive() - chrono::Duration::days(self.config.max_age_days as i64);
        let mut removed = 0;

        if let Ok(entries) = fs::read_dir(&self.config.base_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(date) = NaiveDate::parse_from_str(name, "%Y-%m-%d") {
                        if date < cutoff {
                            if fs::remove_dir_all(entry.path()).is_ok() {
                                removed += 1;
                                info!("Removed old archive: {:?}", entry.path());
                            }
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    /// List all available archive dates
    pub fn list_dates(&self) -> Result<Vec<NaiveDate>> {
        let mut dates = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.config.base_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Ok(date) = NaiveDate::parse_from_str(name, "%Y-%m-%d") {
                            dates.push(date);
                        }
                    }
                }
            }
        }

        dates.sort();
        Ok(dates)
    }

    /// Get total archive size in bytes
    pub fn total_size(&self) -> Result<u64> {
        fn dir_size(path: &Path) -> u64 {
            let mut size = 0;
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let metadata = entry.metadata();
                    if let Ok(meta) = metadata {
                        if meta.is_file() {
                            size += meta.len();
                        } else if meta.is_dir() {
                            size += dir_size(&entry.path());
                        }
                    }
                }
            }
            size
        }

        Ok(dir_size(&self.config.base_dir))
    }
}

/// Archive statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStats {
    pub total_size_bytes: u64,
    pub num_dates: usize,
    pub oldest_date: Option<NaiveDate>,
    pub newest_date: Option<NaiveDate>,
}

impl ArchiveManager {
    /// Get archive statistics
    pub fn stats(&self) -> Result<ArchiveStats> {
        let dates = self.list_dates()?;
        let total_size = self.total_size()?;

        Ok(ArchiveStats {
            total_size_bytes: total_size,
            num_dates: dates.len(),
            oldest_date: dates.first().copied(),
            newest_date: dates.last().copied(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_archive_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config = ArchiveConfig {
            base_dir: temp_dir.path().to_path_buf(),
            max_age_days: 7,
            compression: false,
            compression_level: 6,
        };

        let manager = ArchiveManager::new(config).unwrap();
        let date = NaiveDate::from_ymd_opt(2024, 1, 15).unwrap();
        let data: Vec<u64> = vec![1, 2, 3, 4, 5];

        manager.archive_hourly(date, 10, &data).unwrap();
        let loaded: Vec<u64> = manager.load_hourly(date, 10).unwrap();

        assert_eq!(data, loaded);
    }
}
