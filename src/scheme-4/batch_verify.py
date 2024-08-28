    def batch_verify_messages(self, messages, lskesb, database, tau):
        n = len(messages)
        if n == 0:
            print("No messages to verify.")
            return False

        # Step 1: Choose a vector v = {v1, v2, ..., vn} where vi ∈ [1, 2^τ]
        v = [self.group.random(ZR) for _ in range(n)]

        # Step 2: Perform batch verification
        left_hand_side = self.group.init(G1, 1)  # Initialize as the identity element
        right_hand_side_APK = self.group.init(G1, 1)  # Initialize as the identity element
        right_hand_side_W = self.group.init(GT, 1)  # Initialize as the identity element

        for i in range(n):
            MServ, APKi, PIDi, ti, sigma_i, EIDa = messages[i]

            # Check the freshness of the timestamp ti
            if not self.is_fresh_timestamp(ti):
                print(f"Message {i+1} has an expired timestamp. Skipping.")
                continue

            TSK_prime_i = APKi ** lskesb
            LPKi = PIDi - TSK_prime_i

            if LPKi not in database:
                print(f"Message {i+1} has an invalid LPKi. Skipping.")
                continue

            SSK_prime_i = LPKi ** lskesb
            W = self.query_W(MServ)
            theta_prime_i = self.H1(W, ti, MServ, TSK_prime_i, SSK_prime_i, APKi, PIDi, EIDa)

            left_hand_side *= (g ** (v[i] * sigma_i))
            right_hand_side_APK *= (APKi ** v[i])
            right_hand_side_W *= (W ** (v[i] * theta_prime_i))

        right_hand_side = right_hand_side_APK * right_hand_side_W

        if left_hand_side == right_hand_side:
            print("Batch verification succeeded. All messages accepted.")
            return True
        else:
            print("Batch verification failed. Some or all messages discarded.")
            return False