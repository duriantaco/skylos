import { WidgetType } from '@codemirror/view';
import { Base } from './base';

class Label extends WidgetType {
  constructor(readonly label: string) {
    super();
  }

  eq(other: Label) {
    return this.label === other.label;
  }

  toDOM() {
    return document.createElement('span');
  }
}

class Plain {
  eq(other: Plain) {
    return other === this;
  }

  describe() {
    return 'plain';
  }
}

class Local extends Base {
  matches(other: Local) {
    return other === this;
  }
}

export const widgets = [new Label('a'), new Plain().describe(), new Local().id()];
