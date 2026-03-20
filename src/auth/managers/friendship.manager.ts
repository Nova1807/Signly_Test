import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { AvatarManager } from './avatar.manager';

export interface FriendshipManagerOptions {
  firebaseApp: admin.app.App;
  friendshipsCollection: string;
  friendRequestsCollection: string;
  avatarManager: AvatarManager;
}

export class FriendshipManager {
  constructor(private readonly options: FriendshipManagerOptions) {}

  private get firestore() {
    return this.options.firebaseApp.firestore();
  }

  private buildFriendshipKey(userIdA: string, userIdB: string): { a: string; b: string } {
    if (userIdA === userIdB) {
      throw new BadRequestException('Cannot be friends with yourself');
    }
    return userIdA < userIdB ? { a: userIdA, b: userIdB } : { a: userIdB, b: userIdA };
  }

  async sendFriendRequest(fromUserId: string, targetUsername: string) {
    const firestore = this.firestore;
    const trimmedName = (targetUsername || '').trim();
    if (!trimmedName) {
      throw new BadRequestException('Ziel-Benutzername fehlt');
    }

    const userQuery = await firestore
      .collection('users')
      .where('name', '==', trimmedName)
      .limit(1)
      .get();

    if (userQuery.empty) {
      throw new BadRequestException('Benutzer nicht gefunden');
    }

    const targetDoc = userQuery.docs[0];
    const toUserId = targetDoc.id;

    if (toUserId === fromUserId) {
      throw new BadRequestException('Du kannst dir selbst keine Anfrage senden');
    }

    const { a, b } = this.buildFriendshipKey(fromUserId, toUserId);

    const friendshipSnapshot = await firestore
      .collection(this.options.friendshipsCollection)
      .where('userA', '==', a)
      .where('userB', '==', b)
      .limit(1)
      .get();

    if (!friendshipSnapshot.empty) {
      throw new BadRequestException('Ihr seid bereits befreundet');
    }

    const existingRequestSnapshot = await firestore
      .collection(this.options.friendRequestsCollection)
      .where('fromUserId', '==', fromUserId)
      .where('toUserId', '==', toUserId)
      .where('status', '==', 'pending')
      .limit(1)
      .get();

    if (!existingRequestSnapshot.empty) {
      throw new BadRequestException('Es existiert bereits eine offene Anfrage');
    }

    const reverseRequestSnapshot = await firestore
      .collection(this.options.friendRequestsCollection)
      .where('fromUserId', '==', toUserId)
      .where('toUserId', '==', fromUserId)
      .where('status', '==', 'pending')
      .limit(1)
      .get();

    if (!reverseRequestSnapshot.empty) {
      const reqDoc = reverseRequestSnapshot.docs[0];
      await firestore.runTransaction(async (tx) => {
        tx.update(reqDoc.ref, {
          status: 'accepted',
          respondedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        const friendshipRef = firestore.collection(this.options.friendshipsCollection).doc();
        tx.set(friendshipRef, {
          userA: a,
          userB: b,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      });

      return {
        success: true,
        autoAccepted: true,
        message: 'Gegenseitige Anfrage – Freundschaft wurde erstellt',
      };
    }

    const requestRef = await firestore.collection(this.options.friendRequestsCollection).add({
      fromUserId,
      toUserId,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      success: true,
      autoAccepted: false,
      requestId: requestRef.id,
      message: 'Freundschaftsanfrage gesendet',
    };
  }

  async getIncomingFriendRequests(userId: string) {
    const firestore = this.firestore;

    const snapshot = await firestore
      .collection(this.options.friendRequestsCollection)
      .where('toUserId', '==', userId)
      .where('status', '==', 'pending')
      .get();

    if (snapshot.empty) {
      return { requests: [] };
    }

    const userIds = Array.from(new Set(snapshot.docs.map((d) => (d.data() as any).fromUserId)));

    const userDocs = await Promise.all(
      userIds.map((id) => firestore.collection('users').doc(id).get()),
    );

    const userMap = new Map<string, any>();
    userDocs.forEach((doc) => {
      if (doc.exists) {
        userMap.set(doc.id, doc.data());
      }
    });

    const avatarResults = await Promise.all(
      userIds.map(async (id) => {
        try {
          const avatar = await this.options.avatarManager.getAvatar(id);
          return { id, avatarUrl: avatar.avatarUrl ?? null };
        } catch {
          return { id, avatarUrl: null };
        }
      }),
    );

    const avatarMap = new Map<string, string | null>();
    avatarResults.forEach((item) => {
      avatarMap.set(item.id, item.avatarUrl ?? null);
    });

    const requests = snapshot.docs.map((doc) => {
      const data = doc.data() as any;
      const fromData = userMap.get(data.fromUserId) || {};
      return {
        id: doc.id,
        fromUserId: data.fromUserId,
        username: fromData.name ?? null,
        avatarUrl: avatarMap.get(data.fromUserId) ?? null,
        loginStreak: fromData.loginStreak ?? 0,
        createdAt: data.createdAt ?? null,
      };
    });

    return { requests };
  }

  async respondToFriendRequest(userId: string, requestId: string, accept: boolean) {
    const firestore = this.firestore;
    const requestRef = firestore.collection(this.options.friendRequestsCollection).doc(requestId);
    const requestDoc = await requestRef.get();

    if (!requestDoc.exists) {
      throw new BadRequestException('Anfrage nicht gefunden');
    }

    const data = requestDoc.data() as any;
    if (data.toUserId !== userId) {
      throw new UnauthorizedException('Du darfst diese Anfrage nicht bearbeiten');
    }

    if (data.status !== 'pending') {
      throw new BadRequestException('Anfrage wurde bereits beantwortet');
    }

    if (!accept) {
      await requestRef.update({
        status: 'rejected',
        respondedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return { success: true, accepted: false, message: 'Anfrage abgelehnt' };
    }

    const { a, b } = this.buildFriendshipKey(data.fromUserId, data.toUserId);

    await firestore.runTransaction(async (tx) => {
      tx.update(requestRef, {
        status: 'accepted',
        respondedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      const friendshipRef = firestore.collection(this.options.friendshipsCollection).doc();
      tx.set(friendshipRef, {
        userA: a,
        userB: b,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return { success: true, accepted: true, message: 'Freundschaftsanfrage akzeptiert' };
  }

  async getFriends(userId: string) {
    const firestore = this.firestore;

    const friendshipsSnapshot = await firestore
      .collection(this.options.friendshipsCollection)
      .where('userA', '==', userId)
      .get();

    const friendshipsSnapshot2 = await firestore
      .collection(this.options.friendshipsCollection)
      .where('userB', '==', userId)
      .get();

    const friendIds = new Set<string>();

    friendshipsSnapshot.docs.forEach((doc) => {
      const data = doc.data() as any;
      friendIds.add(data.userB as string);
    });

    friendshipsSnapshot2.docs.forEach((doc) => {
      const data = doc.data() as any;
      friendIds.add(data.userA as string);
    });

    const ids = Array.from(friendIds);
    if (ids.length === 0) {
      return { friends: [] };
    }

    const userDocs = await Promise.all(
      ids.map((id) => firestore.collection('users').doc(id).get()),
    );

    const friends = await Promise.all(
      userDocs
        .filter((doc) => doc.exists)
        .map(async (doc) => {
          const data = doc.data() as any;
          let avatarUrl: string | null = null;
          try {
            const avatar = await this.options.avatarManager.getAvatar(doc.id);
            avatarUrl = avatar.avatarUrl ?? null;
          } catch {
            avatarUrl = null;
          }

          return {
            userId: doc.id,
            username: data.name ?? null,
            avatarUrl,
            loginStreak: data.loginStreak ?? 0,
          };
        }),
    );

    return { friends };
  }
}
