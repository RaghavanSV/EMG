import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import gym
from gym import spaces
from collections import deque
import random
import time
import os
import logging
import argparse
import matplotlib.pyplot as plt
from keras.models import load_model
import pickle
import shutil
import tempfile
import modifier
#import packer_wrapper
import feature_extraction2
#import api
#import malconv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Replay Buffer
class ReplayBuffer:
    def __init__(self, capacity=100000):
        self.buffer = deque(maxlen=capacity)
        self.capacity = capacity

    def add(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size):
        batch = random.sample(self.buffer, min(len(self.buffer), batch_size))
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            torch.FloatTensor(states),
            torch.LongTensor(actions),
            torch.FloatTensor(rewards),
            torch.FloatTensor(next_states),
            torch.FloatTensor(dones)
        )

    def size(self):
        return len(self.buffer)

# Neural Network
class Actor(nn.Module):
    def __init__(self, state_dim, action_dim, hidden_dims=[512, 256]):
        super(Actor, self).__init__()
        layers = []
        prev_dim = state_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.LayerNorm(h_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, action_dim))
        layers.append(nn.Softmax(dim=-1))
        self.model = nn.Sequential(*layers)

    def forward(self, state):
        return self.model(state)

class Critic(nn.Module):
    def __init__(self, state_dim, action_dim, hidden_dims=[512, 256]):
        super(Critic, self).__init__()
        layers = []
        prev_dim = state_dim + action_dim  # State + one-hot encoded action
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.LayerNorm(h_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, 1))
        self.model = nn.Sequential(*layers)
        self.action_dim = action_dim

    def forward(self, state, action):
        action_one_hot = torch.zeros(action.shape[0], self.action_dim, device=action.device)
        action_one_hot.scatter_(1, action.unsqueeze(1), 1.0)
        x = torch.cat([state, action_one_hot], dim=-1)
        return self.model(x)

# Simulated Classifier
class MalwareClassifier:
    def __init__(self):
        #malconv.initialise
        model = load_model('/kaggle/input/model-f/SAC model/malconv.h5',compile=False)
    def predict_proba(self, path):
        # Return probability of being malicious
        #score=api.main(path)   
        with open(file_name, 'rb') as f:
            bytez = f.read()
        padding_char = 256
        maxlen = 2**20  # 1MB
        
        def bytez_to_numpy(bytez, maxlen=maxlen):
            b = np.ones((maxlen,), dtype=np.uint16) * padding_char
            bytez = np.frombuffer(bytez[:maxlen], dtype=np.uint8)
            b[:len(bytez)] = bytez
            return b
        
        X = np.expand_dims(bytez_to_numpy(bytez), axis=0)
        
        output = model.predict(X)
        return output

# Environment
class ExeEvasionEnv(gym.Env):
    def __init__(self, initial_features, file_path, classifier):
        super(ExeEvasionEnv, self).__init__()
        self.num_modifications = 10
        self.action_space = spaces.Discrete(self.num_modifications)
        self.file_path = file_path
        self.classifier = classifier
        self.temp_dir = tempfile.mkdtemp()
        self.max_steps = 10
        self.current_step = 0
        self.actions = {
            0: "pad_overlay",
            1: "append_benign_data_overlay",
            2: "append_benign_binary_overlay",
            3: "add_bytes_to_section_cave",
            4: "add_section_strings",
            5: "add_section_benign_data",
            6: "add_strings_to_overlay",
            7: "add_imports",
            8: "rename_section",
            9: "remove_debug"
        }

        # Define feature keys
        self.feature_keys = [
            'sections', 'imports', 'exports', 'general', 'header',
            'strings', 'directories', 'byte_histogram', 'histogram_entropy'
        ]
        
        # Validate feature keys
        missing_keys = [key for key in self.feature_keys if key not in initial_features]
        if missing_keys:
            logger.error("Missing feature keys: %s", missing_keys)
            raise KeyError(f"Initial features missing keys: {missing_keys}")

        # Combine all features into a single vector
        self.initial_features = np.concatenate([
            np.array(initial_features[key], dtype=np.float32).flatten()
            for key in self.feature_keys
        ])
        self.current_features = self.initial_features.copy()
        
        # Define observation space
        feature_dim = len(self.initial_features)
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(feature_dim,), dtype=np.float32)
        logger.debug("Observation space dimension: %d", feature_dim)

    def reset(self):
        self.current_features = self.initial_features.copy()
        self.current_step = 0
        # Copy original file to temp dir
        self.temp_file = os.path.join(self.temp_dir, "temp.exe")
        shutil.copy(self.file_path, self.temp_file)
        logger.debug("Reset: Initial features shape: %s", self.current_features.shape)
        return self.current_features

    def step(self, action, episode, step):
        logger.debug("Step: Action=%d", action)
        if episode == 4 and step == 9:
            pass
            #modified_exe = packer_wrapper.main(self.current_features)
            #with open(self.file_path, 'wb') as f:
                #f.write(modified_exe)
        else:
            try:
                modified_exe = self._apply_modification(action)
                if not isinstance(modified_exe, bytes):
                    logger.error("Invalid modification result: %s", type(modified_exe))
                    raise ValueError("Modification did not return bytes")

                with open(self.temp_file, 'wb') as f:
                    f.write(modified_exe)
                time.sleep(1)
                with open(self.file_path, 'wb') as f:
                    f.write(modified_exe)
            except Exception as e:
                logger.error(f"Step failed: {e}")
                return self.current_features, -1.0, True, {}

        # Extract new features
        new_features = self._extract_features(modified_exe, self.temp_file)
        self.current_features = np.concatenate([
            np.array(new_features[key], dtype=np.float32).flatten()
            for key in self.feature_keys
        ])
        
        reward = self._calculate_reward()
        self.current_step += 1
        done = self.current_step >= self.max_steps or reward > 0.9
        logger.debug("Step completed: reward=%f, done=%s", reward, done)
        return self.current_features, reward, done, {}

    def _apply_modification(self, action):
        logger.debug("Applying modification: action=%s", self.actions[action])
        return modifier.modify_sample(self.file_path, self.actions[action])

    def _extract_features(self, bytes, exe_path):
        logger.debug("Extracting features from %s", exe_path)
        result = feature_extraction2.process_files(bytes, exe_path)
        if not isinstance(result, dict) or not all(key in result for key in self.feature_keys):
            logger.error("Invalid feature extraction result: %s", result)
            raise ValueError("Feature extraction failed")
        return result

    def _calculate_reward(self):
        prediction = self.classifier.predict_proba(self.temp_file)
        logger.debug("Prediction: %f", prediction)
        return 1.0 - prediction

    def close(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

# SAC
class SAC:
    def __init__(self, env, learning_rate=1e-3, gamma=0.99, tau=0.005, device='cpu'):
        self.env = env
        self.device = device
        self.gamma = gamma
        self.tau = tau
        state_dim = env.observation_space.shape[0]
        action_dim = env.action_space.n
        self.actor = Actor(state_dim, action_dim).to(device)
        self.critic_1 = Critic(state_dim, action_dim).to(device)
        self.critic_2 = Critic(state_dim, action_dim).to(device)
        self.target_critic_1 = Critic(state_dim, action_dim).to(device)
        self.target_critic_2 = Critic(state_dim, action_dim).to(device)
        self.target_critic_1.load_state_dict(self.critic_1.state_dict())
        self.target_critic_2.load_state_dict(self.critic_2.state_dict())
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=learning_rate)
        self.critic_1_optimizer = optim.Adam(self.critic_1.parameters(), lr=learning_rate)
        self.critic_2_optimizer = optim.Adam(self.critic_2.parameters(), lr=learning_rate)
        self.log_alpha = torch.tensor(np.log(0.2), requires_grad=True, device=device)
        self.alpha_optimizer = optim.Adam([self.log_alpha], lr=learning_rate)
        self.target_entropy = -float(action_dim)

    def get_action(self, state, deterministic=False):
        state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            probs = self.actor(state)
        if deterministic:
            action = probs.argmax(dim=-1).item()
        else:
            action = torch.multinomial(probs, 1).item()
        return action

    def train_step(self, replay_buffer, batch_size=128):
        if replay_buffer.size() < batch_size:
            logger.debug("Insufficient buffer size: %d < %d", replay_buffer.size(), batch_size)
            return 0.0, 0.0, 0.0

        states, actions, rewards, next_states, dones = replay_buffer.sample(batch_size)
        states, actions, rewards, next_states, dones = (
            states.to(self.device), actions.to(self.device), rewards.to(self.device),
            next_states.to(self.device), dones.to(self.device)
        )

        # Normalize rewards
        rewards = (rewards - rewards.mean()) / (rewards.std() + 1e-8)

        # Critic update
        with torch.no_grad():
            next_probs = self.actor(next_states)
            next_actions = torch.multinomial(next_probs, 1).squeeze()
            target_q1 = self.target_critic_1(next_states, next_actions)
            target_q2 = self.target_critic_2(next_states, next_actions)
            target_q = rewards + self.gamma * (1 - dones) * torch.min(target_q1, target_q2)

        q1 = self.critic_1(states, actions)
        q2 = self.critic_2(states, actions)
        critic_1_loss = nn.MSELoss()(q1, target_q)
        critic_2_loss = nn.MSELoss()(q2, target_q)

        self.critic_1_optimizer.zero_grad()
        critic_1_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.critic_1.parameters(), max_norm=1.0)
        self.critic_1_optimizer.step()

        self.critic_2_optimizer.zero_grad()
        critic_2_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.critic_2.parameters(), max_norm=1.0)
        self.critic_2_optimizer.step()

        # Actor update
        probs = self.actor(states)
        sampled_actions = torch.multinomial(probs, 1).squeeze()
        q1 = self.critic_1(states, sampled_actions)
        q2 = self.critic_2(states, sampled_actions)
        actor_loss = (self.log_alpha.exp() * torch.log(probs.gather(1, sampled_actions.unsqueeze(1)) + 1e-10) - torch.min(q1, q2)).mean()

        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.actor.parameters(), max_norm=1.0)
        self.actor_optimizer.step()

        # Alpha update
        alpha_loss = -(self.log_alpha * (torch.log(probs + 1e-10) + self.target_entropy).detach()).mean()

        self.alpha_optimizer.zero_grad()
        alpha_loss.backward()
        self.alpha_optimizer.step()

        # Update target networks
        for target_param, param in zip(self.target_critic_1.parameters(), self.critic_1.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)
        for target_param, param in zip(self.target_critic_2.parameters(), self.critic_2.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)

        return actor_loss.item(), critic_1_loss.item(), critic_2_loss.item()

    def save(self, path):
        torch.save({
            'actor': self.actor.state_dict(),
            'critic_1': self.critic_1.state_dict(),
            'critic_2': self.critic_2.state_dict(),
            'target_critic_1': self.target_critic_1.state_dict(),
            'target_critic_2': self.target_critic_2.state_dict(),
            'log_alpha': self.log_alpha
        }, path)
        logger.info(f"Model saved to {path}")

# Main Execution
def main(args):
    device = torch.device("cuda" if torch.cuda.is_available() and args.use_cuda else "cpu")
    logger.info(f"Using device: {device}")
    path=args.path
    evaded=0
    total_exe=0
    rewards = []
    for file in os.listdir(path):
        if file.lower().endswith(".exe") and file != "payload.exe" and file != "temp.exe":
            file_path=file
            if not os.path.exists(file_path):
                logger.warning(f"{file_path} not found. Creating dummy executable.")
                with open(file_path, 'wb') as f:
                    f.write(b'\x00' * 1000)

            # Initialize classifier
            classifier = MalwareClassifier()

            # Extract initial features
            try:
                with open(file_path, "rb") as f:
                    by = f.read()
                features = feature_extraction2.process_files(by, file_path)
                logger.info("Initial features: %s", list(features.keys()))
                for key in features:
                    if key != 'file_name':
                        logger.debug("Feature %s: shape=%s", key, np.array(features[key]).shape)
            except Exception as e:
                logger.error(f"Failed to process file: {e}")
                return
            total_exe+=1
            # Initialize environment and SAC
            env = ExeEvasionEnv(features, file_path, classifier)
            replay_buffer = ReplayBuffer(capacity=args.buffer_capacity)
            sac = SAC(env, learning_rate=args.lr, device=device)
            asn_flag=False


            # Training loop
            best_reward = -np.inf
            for episode in range(args.num_episodes):
                state = env.reset()
                episode_reward = 0
                done = False
                step = 0
                step_flag=True
                while step_flag:
                    action = sac.get_action(state)
                    next_state, reward, done, _ = env.step(action,episode,step)
                    replay_buffer.add(state, action, reward, next_state, done)
                    actor_loss, critic_1_loss, critic_2_loss = sac.train_step(replay_buffer)

                    state = next_state
                    episode_reward += reward
                    step += 1

                    logger.info("File: %s, Episode %d, Step %d: Action=%d, Reward=%f, Actor Loss=%f, Critic1 Loss=%f, Critic2 Loss=%f",
                                file_path, episode, step, action, reward, actor_loss, critic_1_loss, critic_2_loss)
                    logger.debug("Current features shape: %s", env.current_features.shape)
                    if reward > 0.8:
                        step_flag=False
                        break

                if episode_reward > 0.8 and asn_flag==False:
                    asn_flag=True
                    evaded+=1
                rewards.append(episode_reward)
                logger.info("Episode %d: Total Reward=%f, Avg Reward (last 100)=%f",
                            episode, episode_reward, np.mean(rewards[-100:]))

                # Save model if improved
                if episode_reward > best_reward:
                    best_reward = episode_reward
                    sac.save(os.path.join(args.output_dir, "best_model.pth"))

                # Early stopping
                if len(rewards) > 100 and np.mean(rewards[-100:]) > 0.8:
                    logger.info("Early stopping due to high average reward")
                    break

            env.close()

    # Save rewards and plot
    with open(os.path.join(args.output_dir, "rewards.pkl"), 'wb') as f:
        pickle.dump(rewards, f)
    plt.plot(rewards)
    plt.xlabel("Episode")
    plt.ylabel("Total Reward")
    plt.savefig(os.path.join(args.output_dir, "rewards.png"))
    plt.close()
    asn=(evaded/total_exe)*100
    logger.info("Attack Success Rate : ",asn)
    logger.info("Training completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SAC for executable evasion")
    parser.add_argument("--path", type=str, default=".", help="Path to executable")
    parser.add_argument("--num_episodes", type=int, default=5, help="Number of training episodes")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--buffer_capacity", type=int, default=100000, help="Replay buffer capacity")
    parser.add_argument("--output_dir", type=str, default="output", help="Directory for saving models and logs")
    parser.add_argument("--use_cuda", action="store_true", help="Use CUDA if available")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    main(args)