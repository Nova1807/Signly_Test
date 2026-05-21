import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Sign extends Document {
  @Prop({ required: true, unique: true })
  name!: string;

  @Prop({ required: true })
  glbUrl!: string;

  @Prop()
  description?: string;

  @Prop()
  category?: string;

  @Prop()
  eTag?: string;

  @Prop()
  lastModified?: Date;

  @Prop({ default: false })
  needsUpdate!: boolean;

  @Prop()
  lastChecked?: Date;

  createdAt!: Date;
  updatedAt!: Date;
}

export const SignSchema = SchemaFactory.createForClass(Sign);
