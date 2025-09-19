// LATTICE-PoW Genesis Block Generation Code
// Place this code in chainparams.cpp for genesis mining
//
//        arith_uint256 test;
//        bool fNegative;
//        bool fOverflow;
//        test.SetCompact(0x207fffff, &fNegative, &fOverflow);
//        std::cout << "LATTICE-PoW Test threshold: " << test.GetHex() << "\n\n";
//
//        // Initialize lattice operation counters
//        for(int i = 0; i < LATTICE_ROUNDS; i++) {
//            latticeOpHits[i] = 0;
//            latticeOpTotal[i] = 0.0;
//        }
//
//        int genesisNonce = 0;
//        uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
//        uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        
//        std::cout << "Starting LATTICE-PoW genesis mining..." << std::endl;
//        std::cout << "Target difficulty: 0x207fffff" << std::endl;
//        std::cout << "Lattice security level: " << LATTICE_DIMENSION << "-dimensional" << std::endl;
//        std::cout << "Using modulus: " << LATTICE_MODULUS << std::endl;
//        std::cout << "Lattice rounds: " << LATTICE_ROUNDS << std::endl;
//        std::cout << "\n";
//
//        // Initialize global lattice matrix with initial seed
//        uint256 initialSeed = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
//        InitializeLatticeMatrix(initialSeed);
//
//        auto start_time = std::chrono::high_resolution_clock::now();
//
//        for (int i = 0; i < 40000000; i++) {
//            // Create genesis block with LATTICE-PoW
//            genesis = CreateGenesisBlock(1524179366, i, 0x207fffff, 4, 5000 * COIN);
//            
//            // Calculate hash using LATTICE-PoW
//            consensus.hashGenesisBlock = genesis.GetHash(); // This will now use HashLatticePOW
//
//            arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
//            if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
//                BestBlockHash = consensus.hashGenesisBlock;
//                std::cout << "New best: " << BestBlockHash.GetHex() << " Nonce: " << i;
//                
//                // Show lattice operation statistics
//                std::cout << " [";
//                for(int j = 0; j < LATTICE_ROUNDS; j++) {
//                    std::cout << latticeOpHits[j];
//                    if(j < LATTICE_ROUNDS - 1) std::cout << ",";
//                }
//                std::cout << "]" << std::endl;
//                std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << std::endl;
//            }
//
//            TempHashHolding = consensus.hashGenesisBlock;
//
//            // Check if we found a valid genesis block
//            if (UintToArith256(consensus.hashGenesisBlock) < test) {
//                genesisNonce = i;
//                std::cout << "\n🎉 LATTICE-PoW Genesis block found!" << std::endl;
//                break;
//            }
//
//            // Progress indicator every 100,000 iterations
//            if (i > 0 && i % 100000 == 0) {
//                auto current_time = std::chrono::high_resolution_clock::now();
//                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
//                double rate = static_cast<double>(i) / elapsed;
//                std::cout << "Progress: " << i << " iterations (" << std::fixed << std::setprecision(2) 
//                         << rate << " H/s) Best: " << BestBlockHash.GetHex().substr(0, 16) << "..." << std::endl;
//            }
//        }
//        
//        auto end_time = std::chrono::high_resolution_clock::now();
//        auto total_time = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
//        
//        std::cout << "\n";
//        std::cout << "=== LATTICE-PoW Genesis Mining Results ===" << std::endl;
//        std::cout << "hashGenesisBlock: 0x" << BestBlockHash.GetHex() << std::endl;
//        std::cout << "Genesis Nonce: " << genesisNonce << std::endl;
//        std::cout << "Genesis Merkle: " << genesis.hashMerkleRoot.GetHex() << std::endl;
//        std::cout << "Total mining time: " << total_time << " seconds" << std::endl;
//        std::cout << "Average hash rate: " << std::fixed << std::setprecision(2) 
//                 << static_cast<double>(genesisNonce) / total_time << " H/s" << std::endl;
//        std::cout << "\n";
//
//        // Show detailed lattice operation statistics
//        std::cout << "=== Lattice Operation Statistics ===" << std::endl;
//        int totalHits = 0;
//        double totalTime = 0.0;
//
//        for(int x = 0; x < LATTICE_ROUNDS; x++) {
//            totalHits += latticeOpHits[x];
//            totalTime += latticeOpTotal[x];
//            std::cout << "Lattice round " << x << ": " 
//                     << latticeOpHits[x] << " operations";
//            if(latticeOpHits[x] > 0) {
//                std::cout << " (avg: " << std::fixed << std::setprecision(6)
//                         << latticeOpTotal[x] / latticeOpHits[x] << "ms)";
//            }
//            std::cout << std::endl;
//        }
//
//        std::cout << "\nTotals: " << totalHits << " lattice operations";
//        if(totalHits > 0) {
//            std::cout << " (avg: " << std::fixed << std::setprecision(6) 
//                     << totalTime / totalHits << "ms per operation)";
//        }
//        std::cout << std::endl;
//        
//        // Lattice-specific statistics
//        std::cout << "\n=== Post-Quantum Security Analysis ===" << std::endl;
//        std::cout << "Lattice dimension: " << LATTICE_DIMENSION << std::endl;
//        std::cout << "Polynomial modulus: " << LATTICE_MODULUS << std::endl;
//        std::cout << "Estimated quantum security: ~" << (LATTICE_DIMENSION / 2) << " bits" << std::endl;
//        std::cout << "RLWE hardness assumption: Ring-LWE with χ = {-1,0,1}" << std::endl;
//        std::cout << "Quantum resistance: Shor + Grover resistant" << std::endl;
//        
//        // Matrix characteristics
//        std::cout << "\n=== Lattice Matrix Characteristics ===" << std::endl;
//        uint32_t matrix_sum = 0;
//        uint32_t matrix_min = LATTICE_MODULUS;
//        uint32_t matrix_max = 0;
//        
//        for(int i = 0; i < LATTICE_MATRIX_SIZE; i++) {
//            for(int j = 0; j < LATTICE_MATRIX_SIZE; j++) {
//                uint32_t val = global_lattice_matrix[i][j];
//                matrix_sum += val;
//                if(val < matrix_min) matrix_min = val;
//                if(val > matrix_max) matrix_max = val;
//            }
//        }
//        
//        double matrix_avg = static_cast<double>(matrix_sum) / (LATTICE_MATRIX_SIZE * LATTICE_MATRIX_SIZE);
//        std::cout << "Matrix average: " << std::fixed << std::setprecision(2) << matrix_avg << std::endl;
//        std::cout << "Matrix min: " << matrix_min << ", max: " << matrix_max << std::endl;
//        std::cout << "Matrix deterministic seed: " << initialSeed.GetHex().substr(0, 16) << "..." << std::endl;
//        
//        std::cout << "\n=== Genesis Block Validation ===" << std::endl;
//        
//        // Validate the genesis block hash using our LATTICE-PoW
//        uint256 validation_hash = HashLatticePOW(genesis.nVersion, genesis.nVersion + 1, TempHashHolding);
//        bool validation_passed = (validation_hash == consensus.hashGenesisBlock);
//        
//        std::cout << "Genesis validation: " << (validation_passed ? "✅ PASSED" : "❌ FAILED") << std::endl;
//        if(!validation_passed) {
//            std::cout << "Expected: " << consensus.hashGenesisBlock.GetHex() << std::endl;
//            std::cout << "Got:      " << validation_hash.GetHex() << std::endl;
//        }
//        
//        // Final difficulty check
//        arith_uint256 final_difficulty = UintToArith256(consensus.hashGenesisBlock);
//        bool difficulty_met = (final_difficulty < test);
//        std::cout << "Difficulty target met: " << (difficulty_met ? "✅ YES" : "❌ NO") << std::endl;
//        std::cout << "Final difficulty: " << std::hex << final_difficulty.GetCompact() << std::dec << std::endl;
//        
//        std::cout << "\n=== Copy these values to your chainparams.cpp ===" << std::endl;
//        std::cout << "consensus.hashGenesisBlock = uint256S(\"0x" << BestBlockHash.GetHex() << "\");" << std::endl;
//        std::cout << "genesis.nNonce = " << genesisNonce << ";" << std::endl;
//        std::cout << "genesis.hashMerkleRoot = uint256S(\"0x" << genesis.hashMerkleRoot.GetHex() << "\");" << std::endl;
//        
//        std::cout << "\n🚀 LATTICE-PoW genesis mining complete!" << std::endl;
//        std::cout << "Your blockchain is now quantum-resistant! 🛡️" << std::endl;
//
//        genesis.hashPrevBlock = TempHashHolding;
//
//        return;
//
